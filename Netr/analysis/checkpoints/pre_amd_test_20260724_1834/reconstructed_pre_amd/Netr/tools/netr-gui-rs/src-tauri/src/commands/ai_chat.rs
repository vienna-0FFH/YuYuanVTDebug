//! AI 助手对话引擎 (P84)
//!
//! 思路:
//!   - LLM 拿到工具表(JSON Schema)+ 用户对话
//!   - LLM 返回若干 tool_call → 我们调对应 Tauri command 内部函数 → 把结果塞回上下文
//!   - 重复直到 LLM 给出无 tool_call 的最终文本
//!
//! 两个协议各自一套 wire format,这里统一抽象成 `AiTool` / `AiToolCall` / `AiAssistant`:
//!   - OpenAI: function calling, choices[0].message.tool_calls[].{id,function:{name,arguments}}
//!     assistant 消息回包带 tool_calls, 用户回灌每个 tool 的回应:
//!       {role:"tool", tool_call_id, content:<json string>}
//!   - Anthropic: messages tool_use, content blocks 数组,
//!     assistant 消息 content=[{type:text,text}, {type:tool_use, id, name, input}]
//!     user 回灌 content=[{type:tool_result, tool_use_id, content:<json string>}]
//!
//! 危险工具 (`requires_confirm = true`) 前端拦截不走这里 — 后端只执行用户允许过的。
//! 前端会在每个 turn 末尾检查 LLM 想用哪些工具,如果含危险工具则要 user 点同意,
//! 同意后再把那条 ai_chat 请求带 `confirmed_dangerous_ids` 发回。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::sync::Arc;

use tauri::{AppHandle, State};

use crate::commands::debugger_ui::DebuggerHandles;
use crate::commands::mcp_client::McpRegistry;
use crate::util::error::{AppError, AppResult};

// ===== 工具定义 =====

#[derive(Debug, Clone, Serialize)]
pub struct AiTool {
    pub name: Cow<'static, str>,
    pub description: Cow<'static, str>,
    /// JSON Schema for OpenAI / Anthropic input
    pub input_schema: Value,
    /// 是否需要前端确认(driver IOCTL 类)
    pub requires_confirm: bool,
    /// 此工具必须串行执行 — 如 scan_first/scan_next 共享全局扫描状态
    #[serde(default)]
    pub serial: bool,
}

fn tool_table() -> Vec<AiTool> {
    vec![
        AiTool {
            name: "list_processes".into(),
            description: "列出当前系统所有进程 (pid + name + path). 一次返回全部, 不分页".into(),
            input_schema: json!({ "type": "object", "properties": {}, "required": [] }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "restart_debuggee".into(),
            description: "重启当前内置调试器目标并自动沿用当前调试路径. pid 必须是当前已附加目标; 返回新 PID、主线程、入口地址和入口暂停状态.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "resume_execution".into(),
            description: "继续运行当前内置调试器目标。pid 必须是当前已附加目标，tid 必须属于该进程；后端自动沿用当前 Native/VT 调试路径并处理待续行的调试事件。".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的当前暂停线程 ID" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "step_into".into(),
            description: "通过当前内置调试器权威状态机单步步入. pid 必须已附加, tid 必须属于该进程且处于可单步的暂停状态.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的暂停线程 ID" },
                    "count": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "连续步入次数, 默认 1" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "step_over".into(),
            description: "通过当前内置调试器权威状态机单步步过. pid 必须已附加, tid 必须属于该进程且处于可单步的暂停状态.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的暂停线程 ID" },
                    "count": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "连续步过次数, 默认 1" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "step_out".into(),
            description: "通过当前内置调试器权威状态机运行到当前返回地址. pid 必须已附加, tid 必须属于该进程且处于可单步的暂停状态.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的暂停线程 ID" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "get_registers".into(),
            description: "读取当前内置调试器目标中指定线程的通用寄存器、RIP、RSP 和 RFLAGS. 后端自动使用当前调试会话路径; 所有寄存器值以 16 进制字符串返回.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的线程 ID" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "set_registers".into(),
            description: "修改当前内置调试器目标中指定线程的一个或多个寄存器. registers 仅填写要改的字段; 后端先读取权威上下文再应用补丁. 值必须是 16 进制字符串.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "tid": { "type": "integer", "description": "属于 pid 的暂停线程 ID" },
                    "registers": {
                        "type": "object",
                        "description": "可修改 rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8-r15/rip/rflags",
                        "additionalProperties": { "type": "string" }
                    }
                },
                "required": ["pid", "tid", "registers"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "set_breakpoint".into(),
            description: "在当前内置调试器目标设置软件或硬件断点. software 自动遵循当前调试器的软件断点路由; hardware 自动使用当前调试器的硬件断点实现, slot 可省略并自动选择空槽.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "kind": { "type": "string", "enum": ["software", "hardware"] },
                    "address": { "type": "string", "description": "断点地址, 16 进制字符串 0x..." },
                    "slot": { "type": ["integer", "null"], "description": "硬件断点槽 0..3; 省略或 null 时自动选择" },
                    "access": { "type": ["string", "null"], "enum": ["execute", "write", "readwrite", null], "description": "硬件断点访问类型; 默认 execute" },
                    "length": { "type": ["integer", "null"], "description": "硬件断点长度 1/2/4/8; execute 必须为 1" }
                },
                "required": ["pid", "kind", "address"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "clear_breakpoint".into(),
            description: "清除当前内置调试器目标的软件或硬件断点. software 传 address; hardware 可传 slot, 或传 address 由后端定位槽位.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" },
                    "kind": { "type": "string", "enum": ["software", "hardware"] },
                    "address": { "type": ["string", "null"], "description": "软件断点地址; 或用于定位硬件断点槽" },
                    "slot": { "type": ["integer", "null"], "description": "硬件断点槽 0..3" }
                },
                "required": ["pid", "kind"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "list_breakpoints".into(),
            description: "列出当前内置调试器目标的全部软件和硬件断点. 后端自动查询当前调试会话路径.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "当前内置调试器目标 PID" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "list_modules".into(),
            description: "列出某进程已加载的模块 (DLL/exe, base+size+name+path)".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "pid": { "type": "integer", "description": "目标进程 PID" } },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "read_memory".into(),
            description: "从目标进程读字节. size <=4096; 普通结果原样保留. 只有超过通用工具输出上限的结果才会保存为 artifact 并返回预览.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "目标进程 PID, 非 0" },
                    "address": { "type": "string", "description": "16 进制字符串, 形如 \"0x7ff6abcd0000\". 不要传裸数字" },
                    "size":    { "type": "integer", "description": "字节数, 1..4096" }
                },
                "required": ["pid", "address", "size"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "disasm".into(),
            description: "在目标地址反汇编 N 条 x86-64 指令. 自动 read_memory + iced-x86 解码".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "目标进程 PID (必填)" },
                    "address": { "type": "string", "description": "16 进制地址字符串 \"0x...\"" },
                    "count": { "type": "integer", "description": "条数, 1..64, 默认 16" }
                },
                "required": ["pid", "address"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "find_globals".into(),
            description: "扫描模块 .text 找全局指针候选 (按 RIP-rel 引用次数排序). 适合定位 GNames/GUObjectArray/GWorld 等".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"], "description": "目标模块名, 不填则用主 exe" },
                    "top_n": { "type": "integer", "description": "返回前 N, 默认 32" },
                    "min_refs": { "type": "integer", "description": "最小引用门槛, 默认 4" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "aob_scan".into(),
            description: "字节模式扫描 (CE 风格 AOB, ? 占位). \
                          scope=0 全可读地址空间; \
                          scope=1 单模块, 必须给 module_name; \
                          scope=2 自定义区间, 必须给 addr_min/addr_max (16 进制字符串).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "pattern": { "type": "string", "description": "形如 \"48 8B 05 ?? ?? ?? ??\", ? 或 ?? 都是通配" },
                    "scope": { "type": "integer", "enum": [0, 1, 2], "description": "0/1/2 三选一" },
                    "module_name": { "type": ["string", "null"], "description": "scope=1 时必填" },
                    "addr_min": { "type": ["string", "null"], "description": "scope=2 时必填, 16 进制" },
                    "addr_max": { "type": ["string", "null"], "description": "scope=2 时必填, 16 进制" },
                    "max_hits": { "type": "integer", "description": "上限, 默认 5000" }
                },
                "required": ["pid", "pattern", "scope"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "scan_first".into(),
            description: "首次内存扫描 (类似 CE First Scan). \
                          value_type ∈ {i8,i16,i32,i64,u8,u16,u32,u64,f32,f64,string,bytes}. \
                          op ∈ {exact,gt,lt,ge,le,ne}. \
                          根据 value_type 填 number(整数类型) / float(f32/f64) / string / bytes_hex 之一.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "value_type": { "type": "string", "description": "数据类型, 如 'u32' 'i64' 'f32' 'string' 'bytes'" },
                    "op": { "type": "string", "description": "比较操作, 如 'exact' 'gt' 'lt'" },
                    "number": { "type": ["number", "null"], "description": "整数比较值. value_type 是整数类型时填" },
                    "float":  { "type": ["number", "null"], "description": "浮点比较值. value_type=f32/f64 时填" },
                    "string": { "type": ["string", "null"], "description": "字符串. value_type=string 时填" },
                    "bytes_hex": { "type": ["string", "null"], "description": "字节序列(纯 hex, 无空格). value_type=bytes 时填" }
                },
                "required": ["pid", "value_type", "op"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "scan_next".into(),
            description: "在 scan_first 结果上继续过滤 (CE Next Scan). \
                          同样支持 op = exact/gt/lt/ge/le/ne, 加上 changed/unchanged/increasedby/decreasedby. \
                          调用前必须先 scan_first 过.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "op": { "type": "string" },
                    "number": { "type": ["number", "null"] },
                    "float":  { "type": ["number", "null"] },
                    "string": { "type": ["string", "null"] },
                    "bytes_hex": { "type": ["string", "null"] }
                },
                "required": ["pid", "op"]
            }),
            requires_confirm: false,
            serial: true,
        },
        AiTool {
            name: "resolve_symbol".into(),
            description: "把 RVA / VA 反解成 module!symbol+offset (符号表 + 导出表)".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "address": { "type": "string" }
                },
                "required": ["pid", "address"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "lua_eval".into(),
            description: "在嵌入式 Lua 5.4 跑脚本. 完整 API:\n\
                · print(...) / log(...) / io.write(...) — 全部走 output 回传给你, table 会递归 pretty-print\n\
                · read_i8/u8/i16/u16/i32/u32/i64/u64/f32/f64/ptr(pid, addr) — 单值读\n\
                · read_bytes(pid, addr, n) — 返回 table {b1,b2,...}\n\
                · read_string(pid, addr [,max=128]) — utf-8 C 字符串, \\0 截断\n\
                · read_wstring(pid, addr [,max_wchars=128]) — UTF-16LE\n\
                · write_i32/u32/i64/u64/f32/f64(pid, addr, v), write_bytes(pid, addr, table)\n\
                · find_pattern(pid, \"48 89 5C ? ? ? ?\") — 全空间扫描, 返地址或 nil\n\
                · hex(n) — 格式 0xHEX\n\
                · 全局 PID 已绑定当前进程, 调时 pid 可传 0 复用\n\
                runtime 错时 ok=false, output 是已 print 的内容, error 是异常信息".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "code": { "type": "string" }
                },
                "required": ["pid", "code"]
            }),
            requires_confirm: false,
            serial: false,
        },
        // ===== P112 找谁访问/改写此地址 (driver HWBP) =====
        AiTool {
            name: "find_who_accesses".into(),
            description: "找出哪段代码读取/改写了指定内存地址 (CE \"Find out what accesses this address\" 等价). \
                          原理: driver 装硬件断点 (HWBP) WRITE 或 RW, 收集时间窗内的命中, 按 RIP 聚合返回. \
                          典型用法: 扫到血量地址后, 调 mode='write', 让用户在游戏里挨打一下, 返回的 top RIP 就是 damage 函数. \
                          找指针时用 mode='rw'. 调完后 disasm 看那条指令.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer", "description": "目标进程 PID" },
                    "address": { "type": "string", "description": "被监听的内存地址, 16 进制" },
                    "mode": { "type": "string", "enum": ["write", "rw"], "description": "write=只看写入(找谁改写), rw=看读写(找谁访问)" },
                    "length": { "type": "integer", "description": "监听字节数 1/2/4/8, 默认 4. i32 用 4, i64 用 8" },
                    "duration_ms": { "type": "integer", "description": "收集时间窗 ms, 默认 3000, 上限 30000. 用户操作时间不够就加长" }
                },
                "required": ["pid", "address", "mode"]
            }),
            requires_confirm: false,
            serial: true,  // HWBP slot 0 共享, 不能并发跑多个
        },
        // ===== P105 dump 提取 =====
        AiTool {
            name: "dump_region".into(),
            description: "把任意内存区导出到文件. \
                          适合保存可疑数据 / 解密后的 buffer / 加密 payload. \
                          单次上限 256MB. 不可读页 0 填充. \
                          默认写到 %LOCALAPPDATA%\\GuardMetaVSP\\workspace\\dumps\\.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "address": { "type": "string", "description": "16 进制起始地址" },
                    "size": { "type": "integer", "description": "字节数, 上限 256MB" },
                    "out_path": { "type": ["string", "null"], "description": "可选绝对路径, 不传则自动起名" }
                },
                "required": ["pid", "address", "size"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "dump_module".into(),
            description: "导出整个模块 (PE 镜像). 默认 fix_sections=true 把 PE 头改成 raw 视图, \
                          这样导出文件可直接拖进 IDA / x64dbg 分析. \
                          .exe / .dll 自动加 .dump. 扩展名.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"], "description": "模块名, 默认主 exe" },
                    "fix_sections": { "type": "boolean", "description": "默认 true. dump 后写回 SizeOfRawData=VirtualSize, PointerToRawData=VirtualAddress" },
                    "out_path": { "type": ["string", "null"] }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "dump_process".into(),
            description: "把整个进程所有 commit 区域分文件导出 + 写 manifest.json. \
                          适合做事后取证 / 完整快照. 默认 include_images + include_private; \
                          include_mapped 默认 false (大且无用). 总上限 4GB. \
                          单段命名 {base_hex}_{size_hex}.bin, manifest 含 base/size/protect/type.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "out_dir": { "type": ["string", "null"], "description": "可选输出目录" },
                    "include_images": { "type": "boolean", "description": "默认 true, MEM_IMAGE (模块代码)" },
                    "include_private": { "type": "boolean", "description": "默认 true, MEM_PRIVATE (堆/栈)" },
                    "include_mapped": { "type": "boolean", "description": "默认 false, MEM_MAPPED (文件映射, 通常巨大)" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        // ===== P99 签名管理 =====
        AiTool {
            name: "sig_test".into(),
            description: "扫描一条 AOB 签名, 返命中数 + 跟随 RIP 后的目标地址. \
                          unique_target != null 表示唯一命中 (理想). 命中多但 target 都一致也算可用. \
                          0 命中 = 签名失效, 多个不同 target = pattern 太短.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "pattern": { "type": "string", "description": "如 \"48 8B 05 ?? ?? ?? ??\". ? 或 ?? 都是通配" },
                    "follow_rip": { "type": "boolean", "description": "命中后是否解 RIP-rel 取最终地址 (典型: lea/mov [rip+disp])" },
                    "module_name": { "type": ["string", "null"], "description": "限定模块名. 不传 = 主 exe" }
                },
                "required": ["pid", "pattern", "follow_rip"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "sig_derive".into(),
            description: "已知某地址 (比如 find_globals 找到的全局), 自动从该处指令逆推 AOB. \
                          解码 length 字节, 对 RIP-rel disp32 / near branch rel32 自动打 ??. \
                          返回 pattern + 解释 + follow_rip_target (用来 sig_test 验证).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "address": { "type": "string", "description": "已知的特征点指令地址" },
                    "length": { "type": "integer", "description": "抽多少字节, 默认 16, 范围 8..48" }
                },
                "required": ["pid", "address"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "sig_save".into(),
            description: "保存签名到项目 (.gmproj 持久化) + 全局库 (%LOCALAPPDATA% 共享). \
                          AI 调用时请填 source='ai'. 同 id 覆盖.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": ["string", "null"], "description": "稳定 id. 不传则自动生成 {slug}_{ts}" },
                    "name": { "type": "string", "description": "展示名, 如 'DeltaForce GNames'" },
                    "engine": { "type": "array", "items": { "type": "string" }, "description": "[\"UE4\",\"UE5\"]" },
                    "pattern": { "type": "string" },
                    "follow_rip": { "type": "boolean" },
                    "scope": { "type": "string", "description": "main_module / specific_module:foo.dll / all" },
                    "description": { "type": "string", "description": "说明用途 / 命中位置 / 注意事项" },
                    "source": { "type": "string", "enum": ["user", "ai"], "description": "AI 调用填 ai" },
                    "target_exe": { "type": ["string", "null"], "description": "记录针对哪个游戏 exe" }
                },
                "required": ["name", "pattern", "follow_rip", "scope"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "sig_list".into(),
            description: "列项目内所有已保存签名 (含 builtin / user / ai 三种来源).".into(),
            input_schema: json!({ "type": "object", "properties": {}, "required": [] }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "sig_validate".into(),
            description: "扫描已存签名验证仍命中. \
                          sig_id 指定 → 跑一个; 不传 → 跑全部. \
                          返每个签名状态: ok_unique / multiple_hits / miss / drift (地址变了). \
                          失效的签名 AI 应主动 sig_derive 重新发现并 sig_save 覆盖.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "sig_id": { "type": ["string", "null"], "description": "签名 id, 不传 = 全跑" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "sig_delete".into(),
            description: "删除指定 id 的签名.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            }),
            requires_confirm: false,
            serial: false,
        },
        // ===== P91-P94 逆向工具 =====
        AiTool {
            name: "xref_to".into(),
            description: "找所有引用指定地址的指令 (<=IDA Xrefs to). 扫整个模块 .text. \
                          捕捉: call / jmp / lea / mov [rip+disp]. 适合定位函数被谁调用 / 全局变量被谁读写.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "target": { "type": "string", "description": "目标地址, 16 进制" },
                    "module_name": { "type": ["string", "null"], "description": "在哪个模块里搜, 默认主 exe" },
                    "max_hits": { "type": "integer", "description": "结果上限, 默认 256" }
                },
                "required": ["pid", "target"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "xref_from".into(),
            description: "看单条指令引用什么 (<=IDA Xrefs from). 给指令地址, 解码 1 条, 返其所有引用 (rip-rel mem / 近跳目标 / imm64).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "source": { "type": "string", "description": "指令地址, 16 进制" }
                },
                "required": ["pid", "source"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_functions".into(),
            description: "列模块中的函数 (从 .pdata 异常表精确推断). 返回 start/end/size/rva. 配 read_artifact 翻页.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"] },
                    "limit": { "type": "integer", "description": "返多少条, 默认 500" },
                    "offset": { "type": "integer", "description": "起始下标, 默认 0" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "get_function".into(),
            description: "查询包含某地址的函数边界 (start/end/size + 当前偏移). 用 .pdata 表二分.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "address": { "type": "string" }
                },
                "required": ["pid", "address"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_strings".into(),
            description: "扫模块 .rdata/.data/.text 段的 ASCII + UTF-16LE 字符串. 配 xref_to 查谁引用了具体字符串地址.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"] },
                    "min_len": { "type": "integer", "description": "最短字符数, 默认 5" },
                    "limit": { "type": "integer", "description": "上限, 默认 2000" },
                    "filter": { "type": ["string", "null"], "description": "子串过滤, case-insensitive" }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_imports".into(),
            description: "列模块导入表 (DLL + API name + IAT 地址 + 解析后的真实 API 地址). 适合定位用了哪些 Win32 API.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"] }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_exports".into(),
            description: "列模块导出表 (name + RVA + ordinal + 绝对地址). 适合 DLL 接口枚举.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "module_name": { "type": ["string", "null"] }
                },
                "required": ["pid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "call_stack".into(),
            description: "调用栈追踪. 自动 GetThreadContext(tid) 拿 RIP/RSP, 然后栈扫 (4KB 默认) 找返回地址. \
                          线程不需要预先 suspend 但建议先 suspend 否则 RSP 飘. 准确度 ~70% (无 unwind info).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "tid": { "type": "integer" },
                    "max_frames": { "type": "integer", "description": "默认 32, 上限 256" },
                    "stack_scan_bytes": { "type": "integer", "description": "默认 4096, 上限 65536" }
                },
                "required": ["pid", "tid"]
            }),
            requires_confirm: false,
            serial: false,
        },
        // 注解工具 (持久化到 ProjectDoc)
        AiTool {
            name: "set_label".into(),
            description: "给地址打名字标签 (类似 IDA Names). 后续 disasm / resolve_symbol 自动用. 持久化进 .gmproj.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "地址, 16 进制" },
                    "name": { "type": "string", "description": "标签名, 留空则删除" }
                },
                "required": ["address", "name"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "set_comment".into(),
            description: "给地址写注释 (类似 IDA `;` 注释). 持久化进 .gmproj. 留空 name 删除注释.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string" },
                    "name":    { "type": "string", "description": "注释正文(字段名是 name 不是 comment, 复用 SetLabelReq)" }
                },
                "required": ["address", "name"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "define_function".into(),
            description: "声明一个函数 (start address + name + size). 类似 IDA Make Function. 持久化.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string" },
                    "name": { "type": "string" },
                    "size": { "type": "integer" }
                },
                "required": ["address", "name", "size"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_labels".into(),
            description: "列出当前会话/项目里所有自定义标签 (address → name 表).".into(),
            input_schema: json!({ "type": "object", "properties": {}, "required": [] }),
            requires_confirm: false,
            serial: false,
        },
        // ===== P89 联网工具 =====
        AiTool {
            name: "web_search".into(),
            description: "用 DuckDuckGo 搜索. 返回 title + url + snippet. 无需 API key. \
                          做完搜索通常下一步是 web_fetch 拉具体 URL 看正文.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "查询关键词" },
                    "max_results": { "type": "integer", "description": "上限, 默认 8, 1..20" }
                },
                "required": ["query"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "web_fetch".into(),
            description: "拉 http(s) URL 内容. HTML 自动剥 script/style 抽正文. \
                          返回前 16000 字符. 完整正文超出时 truncated=true. \
                          仅供分析参考, 别用来下载二进制.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "完整 URL, 必须 http:// 或 https://" },
                    "max_kb": { "type": "integer", "description": "最多下载 KB, 默认 256, 上限 1024" }
                },
                "required": ["url"]
            }),
            requires_confirm: false,
            serial: false,
        },
        // ===== P89 文件工具 (默认 workspace = %LOCALAPPDATA%\GuardMetaVSP\workspace) =====
        AiTool {
            name: "workspace_root".into(),
            description: "返回 AI workspace 根目录路径. 默认 path 相对此目录解析.".into(),
            input_schema: json!({ "type": "object", "properties": {}, "required": [] }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "read_file".into(),
            description: "读 utf-8 文本文件. 单次最多 512KB. \
                          AI 调用时默认允许绝对路径(用户主动用 AI 等于授权), \
                          相对路径仍 join 到 workspace 根. 可选 offset/length 切片.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "相对 workspace 或绝对路径(后者需 allow_absolute=true)" },
                    "offset": { "type": "integer", "description": "起始字节, 默认 0" },
                    "length": { "type": "integer", "description": "读多少字节, 默认 512KB" },
                    "allow_absolute": { "type": "boolean", "description": "允许绝对路径, 默认 false" }
                },
                "required": ["path"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "write_file".into(),
            description: "覆盖写文件. 不存在则建. 父目录自动创建. 单次最多 4MB.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "allow_absolute": { "type": "boolean", "description": "默认 false, 强制在 workspace 内" }
                },
                "required": ["path", "content"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "append_file".into(),
            description: "追加内容到文件末尾. 不存在则建.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "allow_absolute": { "type": "boolean" }
                },
                "required": ["path", "content"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "list_dir".into(),
            description: "列目录, 返回名字 + 是否目录 + 大小. 最多 500 条, 目录排在文件前.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "目录路径, 用 \".\" 列 workspace 根" },
                    "allow_absolute": { "type": "boolean" }
                },
                "required": ["path"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "make_dir".into(),
            description: "创建目录 (含父目录). 已存在不报错.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "allow_absolute": { "type": "boolean" }
                },
                "required": ["path"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "file_exists".into(),
            description: "检查文件或目录是否存在, 返回 exists/is_file/is_dir/size.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "allow_absolute": { "type": "boolean" }
                },
                "required": ["path"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "delete_file".into(),
            description: "删除文件或目录 (目录递归删). 谨慎使用.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "allow_absolute": { "type": "boolean" }
                },
                "required": ["path"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "read_artifact".into(),
            description: "读取之前工具返回的 artifact 完整内容. 大体积结果 (ue 对象表 / 全局候选 / aob hits / >2KB 内存) \
                          会返回 {artifact_id, summary, size} 而不是全文 — 用这个工具按需取细节. \
                          支持 range 切片避免一次拉太多.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "description": "artifact id (如 art_00000001)" },
                    "offset": { "type": "integer", "description": "起始下标, 默认 0" },
                    "limit": { "type": "integer", "description": "返回元素数, 默认 50, 上限 500" }
                },
                "required": ["id"]
            }),
            requires_confirm: false,
            serial: false,
        },
        AiTool {
            name: "mark_complete".into(),
            description: "明确告知任务已完成. 写一段简短总结, 调用后会立即结束本次 agent 循环. \
                          只在确实完成用户目标时才调用; 否则继续用其他工具.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": { "type": "string", "description": "1-3 句话告诉用户最终结果(关键地址/数值)" }
                },
                "required": ["summary"]
            }),
            requires_confirm: false,
            serial: false,
        },
    ]
}

// ===== 工具调用解析 =====

#[derive(Debug, Deserialize)]
pub struct AiChatReq {
    /// LLM 配置(同 dbg_llm_call)
    pub config: super::llm::LlmConfig,
    /// Provider-neutral canonical history; provider wire format is built only at the HTTP boundary.
    pub messages: Vec<Value>,
    /// 工具开关 — 默认全开, 前端可显式收紧
    pub enabled_tools: Option<Vec<String>>,
    /// max tool call 轮数, 默认 8
    pub max_rounds: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AiChatResp {
    /// 增量 — 这一轮里 LLM 产出的所有消息(assistant + tool 回灌), 前端按顺序追加到历史
    pub new_messages: Vec<Value>,
    /// 这一轮实际跑了几次工具
    pub rounds: u32,
    /// 总 token
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// 是否被工具数上限截断
    pub truncated: bool,
}

// ===== Tool dispatch =====

/// 工具执行结果. Done 表示用户任务完成, 主循环应当退出.
#[derive(Debug)]
pub enum DispatchResult {
    Value(Value),
    Done(String),
}

/// 工具执行 — 直接走对应 command 的内部逻辑, 不走 invoke
async fn dispatch_tool(
    name: &str,
    args: &Value,
    app: &AppHandle,
    session: &Arc<crate::commands::ai_session::AiSession>,
    store: &crate::commands::ai_session::AiSessionStore,
) -> DispatchResult {
    // mark_complete / read_artifact 优先处理
    if name == "mark_complete" {
        let summary = args.get("summary").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if summary.is_empty() || summary.len() < 4 {
            return DispatchResult::Value(json!({
                "ok": false,
                "error": "summary 不能为空, 至少要 4 个字符告诉用户最终结果. 没完成请继续调工具",
            }));
        }
        return DispatchResult::Done(summary);
    }
    if name == "read_artifact" {
        let id = args.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(500) as usize;
        match session.get_artifact(id) {
            None => return DispatchResult::Value(json!({ "ok": false, "error": format!("未知 artifact {id}") })),
            Some(a) => {
                let sliced = match &a.data {
                    Value::Array(arr) => {
                        let n = arr.len();
                        let start = offset.min(n);
                        let end = (start + limit).min(n);
                        json!({
                            "ok": true,
                            "kind": a.kind,
                            "total": n,
                            "offset": start,
                            "count": end - start,
                            "items": &arr[start..end],
                        })
                    }
                    other => {
                        let serialized = other.as_str()
                            .map(ToString::to_string)
                            .unwrap_or_else(|| other.to_string());
                        let total = serialized.chars().count();
                        let start = offset.min(total);
                        let data: String = serialized.chars().skip(start).take(limit).collect();
                        json!({
                            "ok": true,
                            "kind": a.kind,
                            "total_chars": total,
                            "offset": start,
                            "count": data.chars().count(),
                            "data": data,
                            "truncated": start + limit < total,
                        })
                    }
                };
                return DispatchResult::Value(sliced);
            }
        }
    }
    let v = dispatch_payload(name, args, app, session, store).await;
    DispatchResult::Value(v)
}

async fn dispatch_payload(
    name: &str,
    args: &Value,
    app: &AppHandle,
    session: &Arc<crate::commands::ai_session::AiSession>,
    store: &crate::commands::ai_session::AiSessionStore,
) -> Value {
    use tauri::Manager;
    match name {
        "list_processes" => match crate::commands::system::system_list_processes().await {
            Ok(v) => json!({ "ok": true, "processes": v }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        },
        "restart_debuggee" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, None).await {
                return err_payload(error);
            }
            let device = app.state::<crate::ioctl::DeviceState>();
            let freeze = app.state::<Arc<crate::commands::debugger_ui::FreezeStore>>();
            match crate::commands::debugger_ui::dbg_restart_process(
                app.clone(),
                state,
                device,
                freeze,
                pid,
            )
            .await
            {
                Ok(result) => json!({
                    "ok": true,
                    "action": "restart_debuggee",
                    "status": "stopped_at_entry",
                    "old_pid": result.old_pid,
                    "new_pid": result.new_pid,
                    "process_name": result.process_name,
                    "primary_tid": result.primary_tid,
                    "entry_address": format!("0x{:X}", result.entry_address),
                    "stopped_at_entry": result.stopped_at_entry,
                }),
                Err(error) => err_payload(error),
            }
        }
        "resume_execution" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, Some(tid)).await {
                return err_payload(error);
            }
            let device = app.state::<crate::ioctl::DeviceState>();
            match crate::commands::debugger_ui::dbg_resume_thread(state, device, tid).await {
                Ok(previous_suspend_count) => json!({
                    "ok": true,
                    "action": "resume_execution",
                    "status": "running",
                    "pid": pid,
                    "tid": tid,
                    "previous_suspend_count": previous_suspend_count,
                }),
                Err(error) => err_payload(error),
            }
        }
        "step_into" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let count = match step_count(args) { Ok(v) => v, Err(e) => return err_payload(e) };
            let handles = app.state::<Arc<DebuggerHandles>>().inner().clone();
            if let Err(error) = validate_builtin_control_target(&handles, pid, Some(tid)).await {
                return err_payload(error);
            }
            for completed in 0..count {
                if let Err(error) = crate::commands::debugger_ui::dbg_step_into(
                    app.state::<Arc<DebuggerHandles>>(),
                    app.state::<crate::ioctl::DeviceState>(),
                    tid,
                    Some(true),
                ).await {
                    return err_payload(format!("step_into failed after {completed}/{count} steps: {error}"));
                }
                if let Err(error) = crate::commands::debugger_ui::wait_for_builtin_thread_pause(
                    &handles,
                    pid,
                    tid,
                    std::time::Duration::from_secs(30),
                    false,
                ).await {
                    return err_payload(format!("step_into wait failed after {completed}/{count} completed steps: {error}"));
                }
            }
            match crate::commands::debugger_ui::dbg_get_thread_context(tid).await {
                Ok(context) => json!({
                    "ok": true,
                    "action": "step_into",
                    "status": "paused",
                    "pid": pid,
                    "tid": tid,
                    "steps": count,
                    "rip": format!("0x{:X}", context.rip),
                }),
                Err(error) => err_payload(format!("{count} step_into operations completed but final context read failed: {error}")),
            }
        }
        "step_over" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let count = match step_count(args) { Ok(v) => v, Err(e) => return err_payload(e) };
            let handles = app.state::<Arc<DebuggerHandles>>().inner().clone();
            if let Err(error) = validate_builtin_control_target(&handles, pid, Some(tid)).await {
                return err_payload(error);
            }
            let mut last_kind = "single-step";
            let mut last_next_rip = 0u64;
            for completed in 0..count {
                let result = match crate::commands::debugger_ui::dbg_step_over(
                    app.state::<Arc<DebuggerHandles>>(),
                    app.state::<crate::ioctl::DeviceState>(),
                    pid,
                    tid,
                    Some(true),
                ).await {
                    Ok(result) => result,
                    Err(error) => return err_payload(format!("step_over failed after {completed}/{count} steps: {error}")),
                };
                last_kind = result.kind;
                last_next_rip = result.next_rip;
                if let Err(error) = crate::commands::debugger_ui::wait_for_builtin_thread_pause(
                    &handles,
                    pid,
                    tid,
                    std::time::Duration::from_secs(30),
                    false,
                ).await {
                    return err_payload(format!("step_over wait failed after {completed}/{count} completed steps: {error}"));
                }
            }
            match crate::commands::debugger_ui::dbg_get_thread_context(tid).await {
                Ok(context) => json!({
                    "ok": true,
                    "action": "step_over",
                    "status": "paused",
                    "pid": pid,
                    "tid": tid,
                    "steps": count,
                    "last_kind": last_kind,
                    "last_expected_rip": format!("0x{last_next_rip:X}"),
                    "rip": format!("0x{:X}", context.rip),
                }),
                Err(error) => err_payload(format!("{count} step_over operations completed but final context read failed: {error}")),
            }
        }
        "step_out" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, Some(tid)).await {
                return err_payload(error);
            }
            let device = app.state::<crate::ioctl::DeviceState>();
            match crate::commands::debugger_ui::dbg_step_out(state, device, pid, tid).await {
                Ok(return_address) => json!({
                    "ok": true,
                    "action": "step_out",
                    "status": "running_to_return",
                    "pid": pid,
                    "tid": tid,
                    "return_address": format!("0x{return_address:X}"),
                }),
                Err(error) => err_payload(error),
            }
        }
        "get_registers" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, Some(tid)).await {
                return err_payload(error);
            }
            match crate::commands::debugger_ui::dbg_get_thread_context(tid).await {
                Ok(context) => json!({
                    "ok": true,
                    "pid": pid,
                    "tid": tid,
                    "registers": thread_context_registers(&context),
                }),
                Err(error) => err_payload(error),
            }
        }
        "set_registers" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, Some(tid)).await {
                return err_payload(error);
            }
            let mut context = match crate::commands::debugger_ui::dbg_get_thread_context(tid).await {
                Ok(context) => context,
                Err(error) => return err_payload(error),
            };
            let changed = match apply_register_patch(&mut context, args.get("registers")) {
                Ok(changed) => changed,
                Err(error) => return err_payload(error),
            };
            if let Err(error) = crate::commands::debugger_ui::dbg_set_thread_context(context).await {
                return err_payload(error);
            }
            match crate::commands::debugger_ui::dbg_get_thread_context(tid).await {
                Ok(updated) => json!({
                    "ok": true,
                    "pid": pid,
                    "tid": tid,
                    "changed": changed,
                    "registers": thread_context_registers(&updated),
                }),
                Err(error) => err_payload(format!("register write succeeded but verification read failed: {error}")),
            }
        }
        "set_breakpoint" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let kind = match arg_str_required(args, "kind") { Ok(v) => v, Err(e) => return err_payload(e) };
            let address = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, None).await {
                return err_payload(error);
            }
            match kind {
                "software" => {
                    let device = app.state::<crate::ioctl::DeviceState>();
                    match crate::commands::debugger_ui::dbg_sw_bp_set(state, device, pid, address).await {
                        Ok(breakpoint) => json!({
                            "ok": true,
                            "kind": "software",
                            "pid": pid,
                            "address": format!("0x{:X}", breakpoint.address),
                            "original_byte": format!("0x{:02X}", breakpoint.original_byte),
                        }),
                        Err(error) => err_payload(error),
                    }
                }
                "hardware" => {
                    let access = args.get("access").and_then(Value::as_str).unwrap_or("execute");
                    let bp_type = match access {
                        "execute" => 0,
                        "write" => 1,
                        "readwrite" => 3,
                        other => return err_payload(format!("unknown hardware breakpoint access '{other}'")),
                    };
                    let length = args.get("length").and_then(Value::as_u64).unwrap_or(1);
                    let length = match u32::try_from(length) {
                        Ok(length) if matches!(length, 1 | 2 | 4 | 8) => length,
                        _ => return err_payload("hardware breakpoint length must be 1, 2, 4, or 8"),
                    };
                    if bp_type == 0 && length != 1 {
                        return err_payload("execute hardware breakpoints require length=1");
                    }
                    let existing = match crate::commands::hwbp::hwbp_list(
                        app.state::<Arc<DebuggerHandles>>(),
                        pid,
                    ) {
                        Ok(items) => items,
                        Err(error) => return err_payload(error),
                    };
                    let slot = match optional_breakpoint_slot(args) {
                        Ok(Some(slot)) => slot,
                        Ok(None) => match (0..4).find(|slot| !existing.iter().any(|item| item.slot == *slot)) {
                            Some(slot) => slot,
                            None => return err_payload("all four hardware breakpoint slots are in use"),
                        },
                        Err(error) => return err_payload(error),
                    };
                    if existing.iter().any(|item| item.slot == slot) {
                        return err_payload(format!("hardware breakpoint slot {slot} is already in use"));
                    }
                    match crate::commands::hwbp::hwbp_set(
                        app.state::<crate::ioctl::DeviceState>(),
                        app.state::<Arc<DebuggerHandles>>(),
                        std::process::id(),
                        pid,
                        slot,
                        address,
                        length,
                        bp_type,
                    ) {
                        Ok(()) => json!({
                            "ok": true,
                            "kind": "hardware",
                            "pid": pid,
                            "slot": slot,
                            "address": format!("0x{address:X}"),
                            "access": access,
                            "length": length,
                        }),
                        Err(error) => err_payload(error),
                    }
                }
                other => err_payload(format!("unknown breakpoint kind '{other}'")),
            }
        }
        "clear_breakpoint" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let kind = match arg_str_required(args, "kind") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, None).await {
                return err_payload(error);
            }
            match kind {
                "software" => {
                    let address = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
                    match crate::commands::debugger_ui::dbg_sw_bp_clear(
                        state,
                        app.state::<crate::ioctl::DeviceState>(),
                        pid,
                        address,
                    ).await {
                        Ok(()) => json!({
                            "ok": true,
                            "kind": "software",
                            "pid": pid,
                            "address": format!("0x{address:X}"),
                        }),
                        Err(error) => err_payload(error),
                    }
                }
                "hardware" => {
                    let existing = match crate::commands::hwbp::hwbp_list(
                        app.state::<Arc<DebuggerHandles>>(),
                        pid,
                    ) {
                        Ok(items) => items,
                        Err(error) => return err_payload(error),
                    };
                    let requested_address = match args.get("address") {
                        Some(value) if !value.is_null() => match parse_hex_u64_strict(Some(value)) {
                            Ok(address) => Some(address),
                            Err(error) => return err_payload(error),
                        },
                        _ => None,
                    };
                    let slot = match optional_breakpoint_slot(args) {
                        Ok(Some(slot)) => slot,
                        Ok(None) => match requested_address.and_then(|address| {
                            existing.iter().find(|item| item.address == address).map(|item| item.slot)
                        }) {
                            Some(slot) => slot,
                            None => return err_payload("hardware breakpoint clear requires an existing slot or address"),
                        },
                        Err(error) => return err_payload(error),
                    };
                    let Some(current) = existing.iter().find(|item| item.slot == slot) else {
                        return err_payload(format!("hardware breakpoint slot {slot} is empty"));
                    };
                    if requested_address.is_some_and(|address| address != current.address) {
                        return err_payload(format!("slot {slot} does not match the requested hardware breakpoint address"));
                    }
                    match crate::commands::hwbp::hwbp_clear(
                        app.state::<crate::ioctl::DeviceState>(),
                        app.state::<Arc<DebuggerHandles>>(),
                        pid,
                        slot,
                    ) {
                        Ok(()) => json!({
                            "ok": true,
                            "kind": "hardware",
                            "pid": pid,
                            "slot": slot,
                            "address": format!("0x{:X}", current.address),
                        }),
                        Err(error) => err_payload(error),
                    }
                }
                other => err_payload(format!("unknown breakpoint kind '{other}'")),
            }
        }
        "list_breakpoints" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            if let Err(error) = validate_builtin_control_target(state.inner(), pid, None).await {
                return err_payload(error);
            }
            let software = match crate::commands::debugger_ui::dbg_sw_bp_list(state, pid) {
                Ok(items) => items,
                Err(error) => return err_payload(error),
            };
            let hardware = match crate::commands::hwbp::hwbp_list(
                app.state::<Arc<DebuggerHandles>>(),
                pid,
            ) {
                Ok(items) => items,
                Err(error) => return err_payload(error),
            };
            json!({
                "ok": true,
                "pid": pid,
                "software": software.iter().map(|item| json!({
                    "kind": "software",
                    "address": format!("0x{:X}", item.address),
                    "original_byte": format!("0x{:02X}", item.original_byte),
                })).collect::<Vec<_>>(),
                "hardware": hardware.iter().map(|item| json!({
                    "kind": "hardware",
                    "slot": item.slot,
                    "address": format!("0x{:X}", item.address),
                    "length": item.length,
                    "access": hardware_breakpoint_access(item.bp_type),
                })).collect::<Vec<_>>(),
            })
        }
        "list_modules" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            match crate::commands::debugger_ui::dbg_list_modules(state, pid).await {
                Ok(v) => {
                    let mods: Vec<Value> = v.iter().map(|m| json!({
                        "name": m.name,
                        "base": format!("0x{:x}", m.base),
                        "size": m.size,
                        "path": m.path,
                    })).collect();
                    json!({ "ok": true, "count": mods.len(), "modules": mods })
                }
                Err(e) => err_payload(e),
            }
        }
        "read_memory" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let addr = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let size = match arg_u32_required(args, "size") { Ok(v) => v.min(4096), Err(e) => return err_payload(e) };
            let state = app.state::<Arc<DebuggerHandles>>();
            let device = app.state::<crate::ioctl::DeviceState>();
            match crate::commands::debugger_ui::dbg_read_memory(state, device, pid, addr, size).await {
                Ok(v) => {
                    let hex: String = v.bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    json!({
                        "ok": true,
                        "address": format!("0x{:x}", addr),
                        "size": v.bytes.len(),
                        "hex": hex,
                        "truncated": v.truncated,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        "disasm" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let addr = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let count = args.get("count").and_then(|v| v.as_u64()).unwrap_or(16).clamp(1, 64) as usize;
            let size = (count * 16) as u32;
            let state = app.state::<Arc<DebuggerHandles>>();
            let device = app.state::<crate::ioctl::DeviceState>();
            match crate::commands::debugger_ui::dbg_read_memory(state.clone(), device, pid, addr, size).await {
                Ok(rd) => match crate::commands::debugger_ui::dbg_disasm(addr, rd.bytes, None).await {
                    Ok(lines) => {
                        let anno = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
                        let take: Vec<Value> = lines.into_iter().take(count).map(|l| {
                            let label = anno.label_for(l.address);
                            let comment = anno.comment_for(l.address);
                            let func = anno.function_at(l.address);
                            let mut row = json!({
                                "address": format!("0x{:x}", l.address),
                                "bytes_hex": l.bytes_hex,
                                "text": l.text,
                                "len": l.len,
                            });
                            if let Some(n) = label { row["label"] = Value::String(n); }
                            if let Some(c) = comment { row["comment"] = Value::String(c); }
                            if let Some((start, def)) = func {
                                row["function"] = json!({
                                    "name": def.name,
                                    "start": format!("0x{:x}", start),
                                    "size": def.size,
                                    "offset": l.address.saturating_sub(start),
                                });
                            }
                            row
                        }).collect();
                        json!({ "ok": true, "count": take.len(), "lines": take })
                    }
                    Err(e) => err_payload(e),
                },
                Err(e) => err_payload(format!("read_memory failed before disasm: {e}")),
            }
        }
        "find_globals" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let top_n = args.get("top_n").and_then(|v| v.as_u64()).map(|x| x as u32);
            let min_refs = args.get("min_refs").and_then(|v| v.as_u64()).map(|x| x as u32);
            match crate::commands::find_globals::dbg_find_globals(app.clone(), crate::commands::find_globals::FindGlobalsReq {
                pid, module_name, top_n, min_refs,
            }).await {
                Ok(v) => {
                    let result = serde_json::to_value(&v).unwrap_or(json!({}));
                    let total = v.candidates.len();
                    let head: Vec<_> = v.candidates.iter().take(8).map(|c| json!({
                        "address": format!("0x{:x}", c.address),
                        "refs": c.refs,
                    })).collect();
                    if total > 8 {
                        let aid = session.store_artifact(store, "globals",
                            format!("find_globals: {} candidates (text {}KB, refs {})", total, v.text_size/1024, v.rip_refs_total),
                            total as u64, result);
                        json!({
                            "ok": true,
                            "summary": format!("{} 候选, .text {}KB, {} 个 RIP 引用", total, v.text_size/1024, v.rip_refs_total),
                            "top": head,
                            "artifact_id": aid,
                            "hint": "用 read_artifact 拉完整候选表",
                        })
                    } else {
                        json!({ "ok": true, "result": result })
                    }
                }
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "aob_scan" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let pattern = match arg_str_required(args, "pattern") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let scope = args.get("scope").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let max_hits = args.get("max_hits").and_then(|v| v.as_u64()).map(|x| x as u32);
            let addr_min = match args.get("addr_min") {
                Some(v) if !v.is_null() => match parse_hex_u64_strict(Some(v)) {
                    Ok(n) => Some(n), Err(e) => return err_payload(format!("addr_min: {e}")),
                },
                _ => None,
            };
            let addr_max = match args.get("addr_max") {
                Some(v) if !v.is_null() => match parse_hex_u64_strict(Some(v)) {
                    Ok(n) => Some(n), Err(e) => return err_payload(format!("addr_max: {e}")),
                },
                _ => None,
            };
            if scope == 2 && (addr_min.is_none() || addr_max.is_none()) {
                return err_payload("scope=2 (自定义区间) 必须传 addr_min 和 addr_max (16 进制字符串)");
            }
            if scope == 1 && module_name.is_none() {
                return err_payload("scope=1 (单模块) 必须传 module_name");
            }
            match crate::commands::aob_scan::dbg_aob_scan(app.clone(), crate::commands::aob_scan::AobScanReq {
                pid, pattern, scope, module_name, addr_min, addr_max, max_hits,
            }).await {
                Ok(v) => {
                    let total = v.hits.len();
                    let head: Vec<_> = v.hits.iter().take(8).map(|h| json!({
                        "address": format!("0x{:x}", h.address),
                        "module": h.module,
                    })).collect();
                    let result = serde_json::to_value(&v).unwrap_or(json!({}));
                    if total > 8 {
                        let aid = session.store_artifact(store, "aob_hits",
                            format!("aob: {} hits, scanned {}MB", total, v.bytes_scanned/1024/1024),
                            total as u64, result);
                        json!({
                            "ok": true,
                            "summary": format!("{} hits, 扫了 {}MB / {} regions", total, v.bytes_scanned/1024/1024, v.regions_scanned),
                            "top": head,
                            "artifact_id": aid,
                            "truncated": v.truncated,
                        })
                    } else {
                        json!({ "ok": true, "result": result })
                    }
                }
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "scan_first" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let value_type = match arg_str_required(args, "value_type") { Ok(v) => v, Err(e) => return err_payload(e) };
            let op = match arg_str_required(args, "op") { Ok(v) => v, Err(e) => return err_payload(e) };
            let scan_value = parse_scan_value(args);
            let req_json = json!({
                "pid": pid,
                "value_type": value_type,
                "op": op,
                "value": scan_value,
                "addr_min": 0u64,
                "addr_max": 0x7fff_ffff_ffffu64,
            });
            let state = app.state::<Arc<DebuggerHandles>>();
            match serde_json::from_value::<crate::commands::debugger_ui::ScanRequest>(req_json) {
                Ok(req) => match crate::commands::debugger_ui::dbg_scan_first(app.clone(), state, req).await {
                    Ok(v) => json!({
                        "ok": true,
                        "total": v.total,
                        "hits_returned": v.hits.len(),
                        "hits": v.hits.iter().take(64).map(|h| json!({
                            "address": format!("0x{:x}", h.address),
                            "display": h.display,
                        })).collect::<Vec<_>>(),
                        "hint": if v.total > 64 { "前 64 条; 命中多时建议 scan_next 再过滤" } else { "" },
                    }),
                    Err(e) => err_payload(e),
                },
                Err(e) => err_payload(format!("scan_first 参数解析: {e}. value_type 必须是 i8/i16/i32/i64/u8/u16/u32/u64/f32/f64/bytes/string, op 必须是 exact/gt/lt/ge/le/ne/changed/unchanged/increasedby/decreasedby")),
            }
        }
        "scan_next" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let op = match arg_str_required(args, "op") { Ok(v) => v, Err(e) => return err_payload(e) };
            let scan_value = parse_scan_value(args);
            let req_json = json!({ "pid": pid, "op": op, "value": scan_value });
            let state = app.state::<Arc<DebuggerHandles>>();
            match serde_json::from_value::<crate::commands::debugger_ui::ScanNextRequest>(req_json) {
                Ok(req) => match crate::commands::debugger_ui::dbg_scan_next(state, req).await {
                    Ok(v) => json!({
                        "ok": true,
                        "total": v.total,
                        "hits_returned": v.hits.len(),
                        "hits": v.hits.iter().take(64).map(|h| json!({
                            "address": format!("0x{:x}", h.address),
                            "display": h.display,
                        })).collect::<Vec<_>>(),
                        "hint": "scan_first 先执行过吗? 没有的话 scan_next 会失败",
                    }),
                    Err(e) => err_payload(e),
                },
                Err(e) => err_payload(format!("scan_next 参数解析: {e}")),
            }
        }
        "resolve_symbol" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let addr = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            // 自定义 label 优先
            let anno = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
            if let Some(name) = anno.label_for(addr) {
                return json!({
                    "ok": true,
                    "address": format!("0x{:x}", addr),
                    "name": name.clone(),
                    "source": "user_label",
                    "display": name,
                });
            }
            let store = app.state::<crate::commands::symbol::SymbolStore>();
            match crate::commands::symbol::dbg_resolve_symbol(store, pid, addr, false).await {
                Ok(Some(s)) => json!({
                    "ok": true,
                    "address": format!("0x{:x}", s.address),
                    "module": s.module,
                    "name": s.name,
                    "offset": s.offset,
                    "display": if s.offset == 0 { format!("{}!{}", s.module, s.name) }
                               else { format!("{}!{}+0x{:x}", s.module, s.name, s.offset) },
                }),
                Ok(None) => json!({ "ok": true, "found": false, "address": format!("0x{:x}", addr) }),
                Err(e) => err_payload(format!("resolve_symbol: {e}")),
            }
        }
        "lua_eval" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let code = match arg_str_required(args, "code") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            match crate::commands::lua_engine::dbg_lua_run(pid, code).await {
                Ok(v) => {
                    if let Some(err) = v.error {
                        json!({ "ok": false, "error": format!("lua 运行时错误: {err}"), "output": v.output })
                    } else {
                        json!({ "ok": true, "output": v.output })
                    }
                }
                Err(e) => err_payload(e),
            }
        }
        // ===== P112 find_who_accesses =====
        "find_who_accesses" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let address = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let mode = match arg_str_required(args, "mode") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let length = args.get("length").and_then(|v| v.as_u64()).map(|x| x as u32);
            let duration_ms = args.get("duration_ms").and_then(|v| v.as_u64()).map(|x| x as u32);
            let device = app.state::<crate::ioctl::DeviceState>();
            let handles = app.state::<Arc<DebuggerHandles>>();
            match crate::commands::access_watch::dbg_find_who_accesses(
                device, handles,
                crate::commands::access_watch::FindWhoAccessesReq {
                    pid, address, mode, length, duration_ms,
                }
            ).await {
                Ok(r) => json!({
                    "ok": true,
                    "address": format!("0x{:x}", r.address),
                    "mode": r.mode,
                    "duration_ms": r.duration_ms,
                    "hits_total": r.hits_total,
                    "by_rip": r.by_rip.iter().map(|e| json!({
                        "rip": format!("0x{:x}", e.rip),
                        "count": e.count,
                    })).collect::<Vec<_>>(),
                    "note": r.note,
                }),
                Err(e) => err_payload(e),
            }
        }
        // ===== P105 dump =====
        "dump_region" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let address = match arg_str_required(args, "address") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let size = match arg_u64_required(args, "size") { Ok(v) => v, Err(e) => return err_payload(e) };
            let out_path = args.get("out_path").and_then(|v| v.as_str()).map(|s| s.to_string());
            match crate::commands::dump::dbg_dump_region(crate::commands::dump::DumpRegionReq {
                pid, address, size, out_path,
            }).await {
                Ok(r) => json!({
                    "ok": true,
                    "path": r.path,
                    "bytes_requested": r.bytes_requested,
                    "bytes_read": r.bytes_read,
                    "bytes_zero_filled": r.bytes_zero_filled,
                    "chunks_failed": r.chunks_failed,
                }),
                Err(e) => err_payload(e),
            }
        }
        "dump_module" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let fix_sections = args.get("fix_sections").and_then(|v| v.as_bool()).unwrap_or(true);
            let out_path = args.get("out_path").and_then(|v| v.as_str()).map(|s| s.to_string());
            match crate::commands::dump::dbg_dump_module(crate::commands::dump::DumpModuleReq {
                pid, module_name, fix_sections, out_path,
            }).await {
                Ok(r) => json!({
                    "ok": true,
                    "path": r.path,
                    "module": r.module,
                    "base": format!("0x{:x}", r.base),
                    "size": r.size,
                    "fixed": r.fixed,
                    "sections_fixed": r.sections_fixed,
                    "bytes_read": r.bytes_read,
                    "bytes_zero_filled": r.bytes_zero_filled,
                    "chunks_failed": r.chunks_failed,
                }),
                Err(e) => err_payload(e),
            }
        }
        "dump_process" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let out_dir = args.get("out_dir").and_then(|v| v.as_str()).map(|s| s.to_string());
            let include_images = args.get("include_images").and_then(|v| v.as_bool()).unwrap_or(true);
            let include_private = args.get("include_private").and_then(|v| v.as_bool()).unwrap_or(true);
            let include_mapped = args.get("include_mapped").and_then(|v| v.as_bool()).unwrap_or(false);
            match crate::commands::dump::dbg_dump_process(crate::commands::dump::DumpProcessReq {
                pid, out_dir, include_images, include_private, include_mapped,
            }).await {
                Ok(r) => json!({
                    "ok": true,
                    "out_dir": r.out_dir,
                    "manifest_path": r.manifest_path,
                    "regions_total": r.regions_total,
                    "regions_dumped": r.regions_dumped,
                    "total_bytes": r.total_bytes,
                    "aborted_reason": r.aborted_reason,
                    "head": r.regions.iter().take(10).map(|reg| json!({
                        "file": reg.file,
                        "base": format!("0x{:x}", reg.base),
                        "size": reg.size,
                    })).collect::<Vec<_>>(),
                }),
                Err(e) => err_payload(e),
            }
        }
        // ===== P99 签名管理 =====
        "sig_test" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let pattern = match arg_str_required(args, "pattern") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let follow_rip = args.get("follow_rip").and_then(|v| v.as_bool()).unwrap_or(false);
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let scope: u8 = if module_name.is_some() { 1 } else { 1 };
            match crate::commands::sig_discover::sig_test(app.clone(), crate::commands::sig_discover::SigTestReq {
                pid, pattern, follow_rip, scope, module_name, addr_min: None, addr_max: None,
            }).await {
                Ok(r) => json!({
                    "ok": true,
                    "total_hits": r.total_hits,
                    "unique_target": r.unique_target.map(|x| format!("0x{:x}", x)),
                    "hits": r.hits.iter().take(16).map(|h| json!({
                        "at": format!("0x{:x}", h.at),
                        "target": h.target.map(|x| format!("0x{:x}", x)),
                    })).collect::<Vec<_>>(),
                    "bytes_scanned": r.bytes_scanned,
                }),
                Err(e) => err_payload(e),
            }
        }
        "sig_derive" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let address = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let length = args.get("length").and_then(|v| v.as_u64()).map(|x| x as u32);
            match crate::commands::sig_discover::sig_derive(crate::commands::sig_discover::SigDeriveReq {
                pid, address, length,
            }).await {
                Ok(r) => json!({
                    "ok": true,
                    "address": format!("0x{:x}", r.address),
                    "pattern": r.pattern,
                    "bytes_hex": r.bytes_hex,
                    "mask_explanation": r.mask_explanation,
                    "follow_rip_target": r.follow_rip_target.map(|x| format!("0x{:x}", x)),
                    "next_step": "用 sig_test 跑一遍 pattern 看是否唯一 → 唯一就 sig_save",
                }),
                Err(e) => err_payload(e),
            }
        }
        "sig_save" => {
            let name = match arg_str_required(args, "name") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let pattern = match arg_str_required(args, "pattern") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let follow_rip = args.get("follow_rip").and_then(|v| v.as_bool()).unwrap_or(false);
            let scope = match arg_str_required(args, "scope") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let id = args.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
            let engine = args.get("engine").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
                .unwrap_or_default();
            let description = args.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let source = args.get("source").and_then(|v| v.as_str()).map(|s| s.to_string()).or(Some("ai".into()));
            let target_exe = args.get("target_exe").and_then(|v| v.as_str()).map(|s| s.to_string());
            let st = app.state::<Arc<crate::commands::sig_store::SignatureStore>>();
            match crate::commands::sig_store::sig_save(st, crate::commands::sig_store::SaveSigReq {
                id, name, engine, pattern, follow_rip, scope, description, source, target_exe,
            }) {
                Ok(s) => json!({ "ok": true, "id": s.id, "name": s.name, "source": s.source }),
                Err(e) => err_payload(e),
            }
        }
        "sig_list" => {
            let st = app.state::<Arc<crate::commands::sig_store::SignatureStore>>();
            match crate::commands::sig_store::sig_list(st) {
                Ok(v) => {
                    let summary: Vec<Value> = v.iter().take(50).map(|s| json!({
                        "id": s.id, "name": s.name, "source": s.source,
                        "engine": s.engine, "pattern": s.pattern,
                        "follow_rip": s.follow_rip, "scope": s.scope,
                        "last_addr": s.last_addr.map(|x| format!("0x{:x}", x)),
                        "confirmed": s.confirmed,
                        "target_exe": s.target_exe,
                    })).collect();
                    json!({ "ok": true, "total": v.len(), "signatures": summary })
                }
                Err(e) => err_payload(e),
            }
        }
        "sig_validate" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let sig_id = args.get("sig_id").and_then(|v| v.as_str()).map(|s| s.to_string());
            let st = app.state::<Arc<crate::commands::sig_store::SignatureStore>>();
            match crate::commands::sig_discover::sig_validate(app.clone(), st, crate::commands::sig_discover::SigValidateReq { pid, sig_id }).await {
                Ok(r) => {
                    let by_status = {
                        let mut hm: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
                        for s in &r.results { *hm.entry(s.status).or_insert(0) += 1; }
                        hm
                    };
                    json!({
                        "ok": true,
                        "tested": r.tested,
                        "by_status": by_status,
                        "results": r.results.iter().map(|x| json!({
                            "id": x.id, "name": x.name, "status": x.status,
                            "hits": x.hits,
                            "target": x.target.map(|v| format!("0x{:x}", v)),
                            "previous_target": x.previous_target.map(|v| format!("0x{:x}", v)),
                            "note": x.note,
                        })).collect::<Vec<_>>(),
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        "sig_delete" => {
            let id = match arg_str_required(args, "id") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let st = app.state::<Arc<crate::commands::sig_store::SignatureStore>>();
            match crate::commands::sig_store::sig_delete(st, id.clone()) {
                Ok(removed) => json!({ "ok": true, "id": id, "removed": removed }),
                Err(e) => err_payload(e),
            }
        }
        // ===== P91 Xrefs + functions =====
        "xref_to" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let target = match parse_hex_u64_strict(args.get("target")) { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let max_hits = args.get("max_hits").and_then(|v| v.as_u64()).map(|x| x as u32);
            match crate::commands::xref::dbg_xref_to(crate::commands::xref::XrefToReq {
                pid, target, module_name, max_hits,
            }).await {
                Ok(r) => {
                    let head: Vec<Value> = r.hits.iter().take(16).map(|h| json!({
                        "source": format!("0x{:x}", h.source),
                        "kind": h.kind,
                        "mnemonic": h.mnemonic,
                    })).collect();
                    let full = serde_json::to_value(&r.hits).unwrap_or(json!([]));
                    if r.hits.len() > 16 {
                        let aid = session.store_artifact(store, "xrefs",
                            format!("xref_to 0x{:x}: {} hits in {}", target, r.total_hits, r.module),
                            r.total_hits as u64, full);
                        json!({
                            "ok": true,
                            "target": format!("0x{:x}", target),
                            "module": r.module,
                            "total_hits": r.total_hits,
                            "head": head,
                            "artifact_id": aid,
                        })
                    } else {
                        json!({
                            "ok": true,
                            "target": format!("0x{:x}", target),
                            "module": r.module,
                            "total_hits": r.total_hits,
                            "hits": head,
                        })
                    }
                }
                Err(e) => err_payload(e),
            }
        }
        "xref_from" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let source = match parse_hex_u64_strict(args.get("source")) { Ok(v) => v, Err(e) => return err_payload(e) };
            match crate::commands::xref::dbg_xref_from(crate::commands::xref::XrefFromReq { pid, source }).await {
                Ok(r) => json!({
                    "ok": true,
                    "source": format!("0x{:x}", r.source),
                    "instruction": r.instruction,
                    "bytes_hex": r.bytes_hex,
                    "length": r.length,
                    "references": r.references.iter().map(|x| json!({
                        "kind": x.kind, "target": format!("0x{:x}", x.target)
                    })).collect::<Vec<_>>(),
                }),
                Err(e) => err_payload(e),
            }
        }
        "list_functions" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let limit = args.get("limit").and_then(|v| v.as_u64()).map(|x| x as u32);
            let offset = args.get("offset").and_then(|v| v.as_u64()).map(|x| x as u32);
            match crate::commands::functions::dbg_list_functions(crate::commands::functions::ListFunctionsReq {
                pid, module_name, limit, offset,
            }).await {
                Ok(r) => {
                    let head: Vec<Value> = r.functions.iter().take(20).map(|f| json!({
                        "start": format!("0x{:x}", f.start),
                        "size": f.size,
                        "rva": format!("0x{:x}", f.rva),
                    })).collect();
                    let full = serde_json::to_value(&r.functions).unwrap_or(json!([]));
                    let aid = session.store_artifact(store, "functions",
                        format!("{} 函数 in {}", r.total, r.module),
                        r.total as u64, full);
                    json!({
                        "ok": true,
                        "module": r.module,
                        "module_base": format!("0x{:x}", r.module_base),
                        "total": r.total,
                        "returned": r.count,
                        "head_20": head,
                        "artifact_id": aid,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        "get_function" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let address = match parse_hex_u64_strict(args.get("address")) { Ok(v) => v, Err(e) => return err_payload(e) };
            match crate::commands::functions::dbg_get_function(crate::commands::functions::GetFunctionReq { pid, address }).await {
                Ok(r) => match r.function {
                    Some(f) => json!({
                        "ok": true, "found": true,
                        "module": r.module,
                        "start": format!("0x{:x}", f.start),
                        "end": format!("0x{:x}", f.end),
                        "size": f.size,
                        "offset_in_function": r.offset_in_function,
                    }),
                    None => json!({ "ok": true, "found": false, "module": r.module }),
                },
                Err(e) => err_payload(e),
            }
        }
        // ===== P92 strings + imports/exports =====
        "list_strings" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let min_len = args.get("min_len").and_then(|v| v.as_u64()).map(|x| x as u32);
            let limit = args.get("limit").and_then(|v| v.as_u64()).map(|x| x as u32);
            let filter = args.get("filter").and_then(|v| v.as_str()).map(|s| s.to_string());
            match crate::commands::pe_strings::dbg_list_strings(crate::commands::pe_strings::ListStringsReq {
                pid, module_name, min_len, limit, filter,
            }).await {
                Ok(r) => {
                    let head: Vec<Value> = r.strings.iter().take(20).map(|s| json!({
                        "address": format!("0x{:x}", s.address),
                        "encoding": s.encoding,
                        "text": s.text.chars().take(120).collect::<String>(),
                    })).collect();
                    let full = serde_json::to_value(&r.strings).unwrap_or(json!([]));
                    let aid = session.store_artifact(store, "strings",
                        format!("{} 字符串 in {}", r.returned, r.module),
                        r.returned as u64, full);
                    json!({
                        "ok": true,
                        "module": r.module,
                        "total_scanned": r.total,
                        "returned": r.returned,
                        "head_20": head,
                        "artifact_id": aid,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        "list_imports" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            match crate::commands::pe_imports::dbg_list_imports(crate::commands::pe_imports::ListImportsReq { pid, module_name }).await {
                Ok(r) => {
                    let by_dll = {
                        let mut hm: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
                        for i in &r.imports { *hm.entry(i.dll.clone()).or_insert(0) += 1; }
                        let mut v: Vec<_> = hm.into_iter().collect();
                        v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
                        v.into_iter().take(20).collect::<Vec<_>>()
                    };
                    let head: Vec<Value> = r.imports.iter().take(30).map(|i| json!({
                        "dll": i.dll, "name": i.name, "ordinal": i.ordinal,
                        "iat": format!("0x{:x}", i.iat_address),
                        "api": format!("0x{:x}", i.resolved_address),
                    })).collect();
                    let full = serde_json::to_value(&r.imports).unwrap_or(json!([]));
                    let aid = session.store_artifact(store, "imports",
                        format!("{} imports in {}", r.count, r.module),
                        r.count as u64, full);
                    json!({
                        "ok": true,
                        "module": r.module,
                        "count": r.count,
                        "head_30": head,
                        "top_dlls": by_dll.iter().map(|(d, n)| json!([d, n])).collect::<Vec<_>>(),
                        "artifact_id": aid,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        "list_exports" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let module_name = args.get("module_name").and_then(|v| v.as_str()).map(|s| s.to_string());
            match crate::commands::pe_imports::dbg_list_exports(crate::commands::pe_imports::ListExportsReq { pid, module_name }).await {
                Ok(r) => {
                    let head: Vec<Value> = r.exports.iter().take(30).map(|e| json!({
                        "name": e.name, "rva": format!("0x{:x}", e.rva),
                        "ord": e.ordinal,
                        "addr": format!("0x{:x}", e.address),
                    })).collect();
                    let full = serde_json::to_value(&r.exports).unwrap_or(json!([]));
                    let aid = session.store_artifact(store, "exports",
                        format!("{} exports in {}", r.count, r.module),
                        r.count as u64, full);
                    json!({
                        "ok": true,
                        "module": r.module,
                        "count": r.count,
                        "head_30": head,
                        "artifact_id": aid,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        // ===== P94 call stack =====
        "call_stack" => {
            let pid = match arg_u32_required(args, "pid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let tid = match arg_u32_required(args, "tid") { Ok(v) => v, Err(e) => return err_payload(e) };
            let max_frames = args.get("max_frames").and_then(|v| v.as_u64()).map(|x| x as u32);
            let scan = args.get("stack_scan_bytes").and_then(|v| v.as_u64()).map(|x| x as u32);
            let handles = app.state::<Arc<DebuggerHandles>>();
            match crate::commands::call_stack::dbg_call_stack(handles, crate::commands::call_stack::CallStackReq {
                pid, tid, max_frames, stack_scan_bytes: scan,
            }).await {
                Ok(r) => {
                    // 每帧顺手 resolve_symbol
                    let symstore = app.state::<crate::commands::symbol::SymbolStore>();
                    let mut frames = Vec::new();
                    for f in r.frames {
                        let sym = match crate::commands::symbol::dbg_resolve_symbol(symstore.clone(), pid, f.rip, false).await {
                            Ok(Some(s)) => Some(if s.offset == 0 {
                                format!("{}!{}", s.module, s.name)
                            } else {
                                format!("{}!{}+0x{:x}", s.module, s.name, s.offset)
                            }),
                            _ => None,
                        };
                        frames.push(json!({
                            "rip": format!("0x{:x}", f.rip),
                            "rsp": format!("0x{:x}", f.rsp),
                            "module": f.module,
                            "module_offset": f.module_offset.map(|o| format!("0x{:x}", o)),
                            "symbol": sym,
                        }));
                    }
                    json!({
                        "ok": true,
                        "tid": r.tid,
                        "frame_count": frames.len(),
                        "frames": frames,
                        "note": r.note,
                    })
                }
                Err(e) => err_payload(e),
            }
        }
        // ===== P93 注解 =====
        "set_label" => {
            let address = match arg_str_required(args, "address") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let st = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
            match crate::commands::annotations::anno_set_label(st, crate::commands::annotations::SetLabelReq { address: address.clone(), name: name.clone() }) {
                Ok(_) => json!({ "ok": true, "address": address, "name": if name.is_empty() { "<deleted>".into() } else { name } }),
                Err(e) => err_payload(e),
            }
        }
        "set_comment" => {
            let address = match arg_str_required(args, "address") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let st = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
            match crate::commands::annotations::anno_set_comment(st, crate::commands::annotations::SetLabelReq { address: address.clone(), name: name.clone() }) {
                Ok(_) => json!({ "ok": true, "address": address }),
                Err(e) => err_payload(e),
            }
        }
        "define_function" => {
            let address = match arg_str_required(args, "address") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let name = match arg_str_required(args, "name") { Ok(v) => v.to_string(), Err(e) => return err_payload(e) };
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let st = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
            match crate::commands::annotations::anno_define_function(st, crate::commands::annotations::DefineFunctionReq { address: address.clone(), name, size }) {
                Ok(_) => json!({ "ok": true, "address": address, "size": size }),
                Err(e) => err_payload(e),
            }
        }
        "list_labels" => {
            let st = app.state::<Arc<crate::commands::annotations::AnnotationStore>>();
            match crate::commands::annotations::anno_list_labels(st) {
                Ok(v) => json!({ "ok": true, "count": v.len(), "labels": v.iter().map(|(a, n)| json!({"address": a, "name": n})).collect::<Vec<_>>() }),
                Err(e) => err_payload(e),
            }
        }
        // ===== P89 新工具 =====
        "web_search" => crate::commands::web_tools::do_web_search(args).await,
        "web_fetch" => crate::commands::web_tools::do_web_fetch(args).await,
        "workspace_root" => crate::commands::fs_tools::do_workspace_root(),
        "read_file" => crate::commands::fs_tools::do_read_file(&inject_allow_abs(args)),
        "write_file" => crate::commands::fs_tools::do_write_file(&inject_allow_abs(args)),
        "append_file" => crate::commands::fs_tools::do_append_file(&inject_allow_abs(args)),
        "list_dir" => crate::commands::fs_tools::do_list_dir(&inject_allow_abs(args)),
        "make_dir" => crate::commands::fs_tools::do_make_dir(&inject_allow_abs(args)),
        "file_exists" => crate::commands::fs_tools::do_file_exists(&inject_allow_abs(args)),
        "delete_file" => crate::commands::fs_tools::do_delete_file(&inject_allow_abs(args)),
        other if other.starts_with("mcp__") => {
            // P115: MCP 动态工具。命名约定: mcp__<server>__<tool>
            // server 名内不允许有 `__` (前端 upsert 已校验),所以可以从右侧第一个 `__` 切。
            let body = &other["mcp__".len()..];
            match body.find("__") {
                Some(i) => {
                    let server = &body[..i];
                    let tool = &body[i+2..];
                    use tauri::Manager;
                    let registry = app.state::<Arc<McpRegistry>>();
                    match crate::commands::mcp_client::call_tool_internal(
                        registry.inner(), server, tool, args.clone()).await
                    {
                        Ok(v) => json!({ "ok": true, "result": v }),
                        Err(e) => json!({ "ok": false, "error": e.to_string() }),
                    }
                }
                None => json!({ "ok": false, "error": format!("mcp 工具名格式错误 {other}, 期望 mcp__<server>__<tool>") }),
            }
        }
        other => json!({ "ok": false, "error": format!("未知工具 {other}") }),
    }
}

/// 解析 16 进制地址. 严格模式: 必须是字符串 "0x..." 或 "...". 拒裸数字 (>2^53 在 JSON 已丢精度).
fn parse_hex_u64_strict(v: Option<&Value>) -> Result<u64, String> {
    let Some(val) = v else { return Err("缺少地址参数".into()) };
    let Some(s) = val.as_str() else {
        return Err("地址必须是十六进制字符串(如 \"0x7ff6abcd0000\"). 不要传裸数字, JSON 数字 >2^53 会丢精度".into());
    };
    let s = s.trim();
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16)
        .map_err(|e| format!("无法解析地址 '{}': {e}", s))
}

/// 软模式 — 老调用点. pid 之类小数字仍可裸数字.
fn parse_hex_u64(v: Option<&Value>) -> u64 {
    let Some(s) = v else { return 0 };
    if let Some(n) = s.as_u64() { return n; }
    let st = s.as_str().unwrap_or("0").trim();
    let st = st.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(st, 16).unwrap_or(0)
}

/// 必填 u32 参数. None 或 0 → Err.
fn arg_u32_required(args: &Value, key: &str) -> Result<u32, String> {
    let Some(v) = args.get(key) else { return Err(format!("缺少必填参数 {key}")) };
    let Some(n) = v.as_u64() else { return Err(format!("{key} 必须是非负整数")) };
    if n == 0 || n > u32::MAX as u64 { return Err(format!("{key} 不能为 0 或超过 u32 范围")); }
    Ok(n as u32)
}

fn arg_u64_required(args: &Value, key: &str) -> Result<u64, String> {
    let Some(v) = args.get(key) else { return Err(format!("缺少必填参数 {key}")) };
    if let Some(n) = v.as_u64() { return Ok(n); }
    Err(format!("{key} 必须是非负整数"))
}

fn arg_str_required<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("缺少必填参数 {key}"))
}

fn err_payload(msg: impl ToString) -> Value {
    json!({ "ok": false, "error": msg.to_string() })
}

const TOOL_OUTPUT_MAX_LINES: usize = 2_000;
const TOOL_OUTPUT_MAX_BYTES: usize = 50 * 1024;

fn take_prefix_bytes(text: &str, maximum: usize) -> String {
    let mut bytes = 0usize;
    let mut result = String::new();
    for character in text.chars() {
        let size = character.len_utf8();
        if bytes + size > maximum {
            break;
        }
        result.push(character);
        bytes += size;
    }
    result
}

fn take_suffix_bytes(text: &str, maximum: usize) -> String {
    let mut bytes = 0usize;
    let mut result = String::new();
    for character in text.chars().rev() {
        let size = character.len_utf8();
        if bytes + size > maximum {
            break;
        }
        result.insert(0, character);
        bytes += size;
    }
    result
}

fn bounded_tool_preview(text: &str, marker: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let marker_bytes = marker.len();
    if TOOL_OUTPUT_MAX_LINES <= 4 || TOOL_OUTPUT_MAX_BYTES <= marker_bytes + 4 {
        return take_prefix_bytes(marker, TOOL_OUTPUT_MAX_BYTES);
    }
    let content_lines = TOOL_OUTPUT_MAX_LINES - 4;
    let head_lines = content_lines.div_ceil(2);
    let tail_lines = content_lines / 2;
    let (head, tail) = if lines.len() <= content_lines {
        (text.to_string(), String::new())
    } else {
        (
            lines[..head_lines].join("\n"),
            lines[lines.len() - tail_lines..].join("\n"),
        )
    };
    let preview = if tail.is_empty() {
        format!("{head}\n\n{marker}")
    } else {
        format!("{head}\n\n{marker}\n\n{tail}")
    };
    if preview.len() <= TOOL_OUTPUT_MAX_BYTES {
        return preview;
    }
    let available = TOOL_OUTPUT_MAX_BYTES.saturating_sub(marker_bytes + 4);
    let sampled = if tail.is_empty() { head } else { format!("{head}\n{tail}") };
    let bounded_head = take_prefix_bytes(&sampled, available.div_ceil(2));
    let bounded_tail = take_suffix_bytes(&sampled, available / 2);
    if bounded_tail.is_empty() {
        format!("{bounded_head}\n\n{marker}")
    } else {
        format!("{bounded_head}\n\n{marker}\n\n{bounded_tail}")
    }
}

fn tool_result_text(value: &Value) -> String {
    value
        .get("output")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn tool_result_for_context(
    name: &str,
    value: Value,
    session: &Arc<crate::commands::ai_session::AiSession>,
    store: &crate::commands::ai_session::AiSessionStore,
) -> Value {
    let serialized = tool_result_text(&value);
    let size = serialized.len();
    let line_count = serialized.bytes().filter(|byte| *byte == b'\n').count() + 1;
    if size <= TOOL_OUTPUT_MAX_BYTES && line_count <= TOOL_OUTPUT_MAX_LINES {
        return value;
    }
    let artifact_id = session.store_artifact(
        store,
        &format!("tool_result:{name}"),
        format!("{name} produced {size} bytes"),
        size as u64,
        value.clone(),
    );
    let marker = format!(
        "... output truncated; full content saved as artifact {artifact_id}; use read_artifact(id, offset, limit) ..."
    );
    let preview = bounded_tool_preview(&serialized, &marker);
    json!({
        "ok": value.get("ok").cloned().unwrap_or(Value::Bool(true)),
        "artifact_id": artifact_id,
        "size_bytes": size,
        "line_count": line_count,
        "preview": preview,
        "truncated": true,
        "hint": "Use read_artifact with offset/limit to inspect the stored result",
    })
}

fn thread_context_registers(
    context: &crate::commands::debugger_ui::ThreadContextView,
) -> Value {
    json!({
        "rax": format!("0x{:X}", context.rax),
        "rbx": format!("0x{:X}", context.rbx),
        "rcx": format!("0x{:X}", context.rcx),
        "rdx": format!("0x{:X}", context.rdx),
        "rsi": format!("0x{:X}", context.rsi),
        "rdi": format!("0x{:X}", context.rdi),
        "rbp": format!("0x{:X}", context.rbp),
        "rsp": format!("0x{:X}", context.rsp),
        "r8": format!("0x{:X}", context.r8),
        "r9": format!("0x{:X}", context.r9),
        "r10": format!("0x{:X}", context.r10),
        "r11": format!("0x{:X}", context.r11),
        "r12": format!("0x{:X}", context.r12),
        "r13": format!("0x{:X}", context.r13),
        "r14": format!("0x{:X}", context.r14),
        "r15": format!("0x{:X}", context.r15),
        "rip": format!("0x{:X}", context.rip),
        "rflags": format!("0x{:X}", context.rflags),
        "cs": format!("0x{:X}", context.cs),
        "ss": format!("0x{:X}", context.ss),
    })
}

fn apply_register_patch(
    context: &mut crate::commands::debugger_ui::ThreadContextView,
    registers: Option<&Value>,
) -> Result<Vec<String>, String> {
    let registers = registers
        .and_then(Value::as_object)
        .ok_or_else(|| "registers must be a non-empty object".to_string())?;
    if registers.is_empty() {
        return Err("registers must contain at least one register".into());
    }
    let mut changed = Vec::with_capacity(registers.len());
    for (name, raw_value) in registers {
        let normalized = name.to_ascii_lowercase();
        let value = parse_hex_u64_strict(Some(raw_value))
            .map_err(|error| format!("{normalized}: {error}"))?;
        match normalized.as_str() {
            "rax" => context.rax = value,
            "rbx" => context.rbx = value,
            "rcx" => context.rcx = value,
            "rdx" => context.rdx = value,
            "rsi" => context.rsi = value,
            "rdi" => context.rdi = value,
            "rbp" => context.rbp = value,
            "rsp" => context.rsp = value,
            "r8" => context.r8 = value,
            "r9" => context.r9 = value,
            "r10" => context.r10 = value,
            "r11" => context.r11 = value,
            "r12" => context.r12 = value,
            "r13" => context.r13 = value,
            "r14" => context.r14 = value,
            "r15" => context.r15 = value,
            "rip" => context.rip = value,
            "rflags" => {
                context.rflags = u32::try_from(value)
                    .map_err(|_| format!("rflags value 0x{value:X} exceeds 32 bits"))?;
            }
            other => return Err(format!("unsupported register '{other}'")),
        }
        changed.push(normalized);
    }
    changed.sort();
    Ok(changed)
}

fn optional_breakpoint_slot(args: &Value) -> Result<Option<u32>, String> {
    let Some(value) = args.get("slot") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    match value.as_u64() {
        Some(slot) if slot < 4 => Ok(Some(slot as u32)),
        _ => Err("hardware breakpoint slot must be an integer from 0 to 3".into()),
    }
}

fn step_count(args: &Value) -> Result<u32, String> {
    match args.get("count") {
        None | Some(Value::Null) => Ok(1),
        Some(value) => match value.as_u64() {
            Some(count @ 1..=1000) => Ok(count as u32),
            _ => Err("step count must be an integer from 1 to 1000".into()),
        },
    }
}

fn hardware_breakpoint_access(bp_type: u8) -> &'static str {
    match bp_type {
        0 => "execute",
        1 => "write",
        3 => "readwrite",
        _ => "unknown",
    }
}

async fn validate_builtin_control_target(
    state: &Arc<DebuggerHandles>,
    pid: u32,
    tid: Option<u32>,
) -> Result<(), String> {
    match crate::commands::debugger_ui::builtin_target_mode(state, pid) {
        Some(_) => {}
        None => {
            return Err(format!(
                "PID {pid} is not an active built-in debugger target"
            ))
        }
    }
    if let Some(tid) = tid {
        let threads = crate::commands::debugger_ui::dbg_list_threads(pid)
            .await
            .map_err(|error| format!("unable to validate threads for PID {pid}: {error}"))?;
        if !threads.iter().any(|thread| thread.tid == tid && thread.owner_pid == pid) {
            return Err(format!("thread {tid} does not belong to target PID {pid}"));
        }
    }
    Ok(())
}

/// AI 调 fs 工具时默认放宽绝对路径限制 — 用户主动用 AI 等于授权.
/// LLM 仍可显式传 allow_absolute=false 收紧.
fn inject_allow_abs(args: &Value) -> Value {
    let mut v = args.clone();
    if let Value::Object(m) = &mut v {
        if !m.contains_key("allow_absolute") {
            m.insert("allow_absolute".into(), Value::Bool(true));
        }
    }
    v
}

fn parse_scan_value(args: &Value) -> Value {
    json!({
        "number": args.get("number"),
        "float": args.get("float"),
        "string": args.get("string"),
        "bytes": args.get("bytes_hex").and_then(|v| v.as_str()).map(|s| {
            let s = s.trim();
            let mut out = Vec::with_capacity(s.len() / 2);
            let bytes = s.as_bytes();
            let mut i = 0;
            while i + 2 <= bytes.len() {
                let hex = std::str::from_utf8(&bytes[i..i+2]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                i += 2;
            }
            out
        }),
    })
}

// ===== 主入口 =====

fn system_prompt() -> &'static str {
    "你是 GuardMeta 调试器的 AI 助手, 集成 CE 风格内置调试器, 可以驾驶它完成多步任务.\n\
     \n\
     工作循环(默认可达 200 轮, 直到调 mark_complete):\n\
     1. 摸清目标: list_processes / list_modules\n\
     2. 静态逆向: list_functions / list_strings / list_imports / list_exports\n\
        xref_to(谁引用此地址) / xref_from(此指令引用什么) / get_function(此地址属于哪个函数)\n\
     3. 定位: find_globals / aob_scan / scan_first → scan_next 收敛\n\
     4. 读取: read_memory / disasm / resolve_symbol / call_stack / get_registers\n\
        find_who_accesses(pid, address, mode='write'|'rw'): 装 HWBP 找出谁改/谁访问了内存 \
        (CE Find out what accesses this address 等价). 找血量 damage 函数 / 找指针都靠这个.\n\
     5. 调试控制: resume_execution 直接放行当前暂停线程; step_into / step_over / step_out 驱动当前暂停线程; \
        restart_debuggee 重启当前启动型会话并重新停在入口; \
        set_registers 修改寄存器; set_breakpoint / clear_breakpoint / list_breakpoints 管理断点. \
        必须使用当前目标 PID/TID, 调试路径由后端当前会话自动选择.\n\
     6. 注解: set_label / set_comment / define_function (持久化到项目, disasm 自动附加)\n\
     7. 脚本: lua_eval 跑自定义逻辑\n\
     8. 文件: read_file / write_file / append_file / list_dir / make_dir / \
        file_exists / delete_file (默认相对 workspace, AI 调用默认允许绝对路径)\n\
     9. 联网: web_search 查文档/资料, web_fetch 拉具体 URL 看正文\n\
     10. 完成时调 mark_complete(summary='...') 立即终止\n\
     \n\
     地址必须是 16 进制字符串 (\"0x7ff6abcd0000\"), 不要传裸数字 — JSON 数字 >2^53 丢精度.\n\
     pid 必须是非 0 整数. size/count 等也要给真实值, 不写就用默认上限.\n\
     \n\
     大体积工具结果(find_globals/aob_scan/大块 read_memory)\n\
     不会直接返完整数据, 只回 {summary, top N, artifact_id}.\n\
     需要细节时调 read_artifact(id, offset, limit) 翻页.\n\
     \n\
     并行: 同一轮里可以同时返多个 tool_use, 没有依赖的会并发执行.\n\
     scan_first/scan_next 例外, 必须串行(共享全局扫描状态).\n\
     \n\
     签名工作流(目标 = 自动维护项目里的 AOB 库):\n\
     · 用户切到新游戏时, 先 sig_validate(pid) — 一次性看全部已有签名状态\n\
     · status=miss/multiple_hits/drift 的签名失效, 用 find_globals 重新定位真实地址\n\
     · 拿到新地址后, sig_derive(pid, address, length=16) 自动生成新 pattern\n\
     · sig_test(pid, pattern, follow_rip) 验证唯一命中 → 唯一就 sig_save(source='ai', target_exe='xxx.exe')\n\
     · 全部命中后告诉用户 '已更新 N 个签名, 跨次启动可复用'\n\
     · 新发现的全局 (如 GEngine/ViewMatrix 之类), 先 sig_derive 提 pattern, 再 sig_save 入库\n\
     \n\
     原则:\n\
     - 不要让用户手动给 PID/地址, 自己用工具查\n\
     - 不盲调; 看结果再决定下一步, 错了就换思路\n\
     - 工具失败时 ok=false 会附 error 字段, 读完调整重试\n\
     - 完成任务再 mark_complete (summary 必须 >= 4 字符); 没完成就继续\n\
     - 中文回复, 关键地址/数值写到结论里"
}

// 旧 dbg_ai_chat 在 P87.1 之后由 dbg_ai_run 取代 (流式 + 取消 + artifact + 长循环 + 并行).
// 这里保留命令名兼容老前端调用 — 把单次请求转 forward 到 dbg_ai_run 的简化版,
// 但前端已切到 ai-run, 这里只为防止冷启动崩.
#[tauri::command]
pub async fn dbg_ai_chat(
    _app: AppHandle,
    _handles: State<'_, Arc<DebuggerHandles>>,
    _req: AiChatReq,
) -> AppResult<AiChatResp> {
    Err(AppError::Internal("dbg_ai_chat 已废弃, 请用 dbg_ai_run".into()))
}

fn filter_tools(enabled: Option<&[String]>) -> Vec<AiTool> {
    let all = tool_table();
    match enabled {
        None => all,
        Some(en) => all.into_iter().filter(|t| en.iter().any(|n| n.as_str() == t.name.as_ref())).collect(),
    }
}

/// P115: 把当前 connected MCP server 的工具拼到工具表末尾.
/// 名字加 `mcp__<server>__<tool>` 前缀, dispatch 时 router 按前缀分流.
async fn append_mcp_tools(registry: &McpRegistry, tools: &mut Vec<AiTool>) {
    let list = crate::commands::mcp_client::list_ai_visible_tools(registry).await;
    for (server, tname, desc, schema) in list {
        let full_name = format!("mcp__{server}__{tname}");
        let desc_str = format!(
            "[MCP/{server}] {}",
            desc.unwrap_or_else(|| format!("调用 MCP server {server} 的工具 {tname}"))
        );
        tools.push(AiTool {
            name: Cow::Owned(full_name),
            description: Cow::Owned(desc_str),
            input_schema: schema,
            requires_confirm: false,
            serial: false,
        });
    }
}

// ===== P87 Agent Loop (流式 + 取消 + 并行 + artifact + 自终止 + 持久化) =====

use crate::commands::ai_session::{AiSession, AiSessionStore, append_log, append_log_durable, ensure_history_snapshot, list_sessions, load_session, load_session_history, delete_session, SessionFileInfo};

const CONTEXT_COMPACTION_KEEP_TURNS: usize = 2;
const COMPACTION_TOOL_OUTPUT_MAX_CHARS: usize = 2_000;

const OPENCODE_COMPACTION_BUFFER_TOKENS: u64 = 20_000;
const OPENCODE_PRESERVE_RECENT_MIN_TOKENS: u64 = 2_000;
const OPENCODE_PRESERVE_RECENT_MAX_TOKENS: u64 = 8_000;
const OPENCODE_OUTPUT_TOKEN_MAX: u32 = 32_000;
const ANTHROPIC_FALLBACK_OUTPUT_TOKENS: u32 = 4_096;

#[derive(Debug, Clone, Copy, Default)]
struct ModelLimits {
    context: Option<u64>,
    input: Option<u64>,
    output: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct LlmUsage {
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    total: u64,
}

impl LlmUsage {
    fn context_tokens(self) -> u64 {
        if self.total > 0 {
            self.total
        } else {
            self.input
                .saturating_add(self.output)
                .saturating_add(self.cache_read)
                .saturating_add(self.cache_write)
        }
    }
}

fn catalog_model_limits(config: &super::llm::LlmConfig) -> ModelLimits {
    let provider = config.provider.to_ascii_lowercase();
    let model = config.model.to_ascii_lowercase();
    // The public models.dev catalog reports the trusted Opus/Fable profile as
    // a 1M context with a 128K model output ceiling and no separate input cap.
    // GPT-5.5/5.6 compatibility aliases intentionally share that profile.
    let opus_1m = model == "opus"
        || model.contains("opus-latest")
        || model.contains("opus-4.6")
        || model.contains("opus-4-6")
        || model.contains("opus-4.7")
        || model.contains("opus-4-7")
        || model.contains("opus-4.8")
        || model.contains("opus-4-8");
    if model.contains("gpt-5.5")
        || model.contains("gpt-5.6")
        || opus_1m
        || model.contains("fable")
    {
        return ModelLimits { context: Some(1_000_000), input: None, output: Some(128_000) };
    }
    if model.contains("opus-4.5") || model.contains("opus-4-5") {
        return ModelLimits { context: Some(200_000), input: None, output: Some(64_000) };
    }
    if model.contains("opus-4.1") || model.contains("opus-4-1") || model.ends_with("opus-4") {
        return ModelLimits { context: Some(200_000), input: None, output: Some(32_000) };
    }
    if provider == "anthropic" && model.contains("claude") {
        return ModelLimits { context: Some(200_000), input: None, output: Some(8_192) };
    }
    if provider == "openai" {
        if model.contains("gpt-4.1") {
            return ModelLimits { context: Some(1_000_000), input: None, output: Some(32_768) };
        }
        if model.contains("gpt-4o") || model.contains("gpt-4-turbo") {
            return ModelLimits { context: Some(128_000), input: None, output: Some(16_384) };
        }
    }
    ModelLimits::default()
}

fn model_limits(config: &super::llm::LlmConfig) -> ModelLimits {
    let catalog = catalog_model_limits(config);
    ModelLimits {
        context: config.context_tokens.or(catalog.context),
        input: config.input_tokens.or(catalog.input),
        output: config.output_tokens.or(catalog.output),
    }
}

fn max_output_tokens(config: &super::llm::LlmConfig) -> Option<u32> {
    let model_output = model_limits(config).output.and_then(|value| u32::try_from(value).ok());
    let request_cap = config.output_token_max
        .filter(|value| *value > 0)
        .unwrap_or(OPENCODE_OUTPUT_TOKEN_MAX);
    Some(model_output.filter(|value| *value > 0).map_or(request_cap, |model_value| {
        request_cap.min(model_value)
    }))
}

fn output_budget_for_request(config: &super::llm::LlmConfig) -> u32 {
    max_output_tokens(config).unwrap_or_else(|| {
        if config.provider == "anthropic" {
            ANTHROPIC_FALLBACK_OUTPUT_TOKENS
        } else {
            OPENCODE_OUTPUT_TOKEN_MAX
        }
    })
}

fn usable_input_tokens(config: &super::llm::LlmConfig) -> Option<u64> {
    let limits = model_limits(config);
    let output = max_output_tokens(config).map(u64::from)?;
    if let Some(input) = limits.input {
        let reserved = config.compaction_reserved_tokens
            .unwrap_or(output.min(OPENCODE_COMPACTION_BUFFER_TOKENS));
        return Some(input.saturating_sub(reserved));
    }
    limits.context.map(|context| context.saturating_sub(output))
}

fn preserve_recent_budget(config: &super::llm::LlmConfig) -> u64 {
    usable_input_tokens(config)
        .map(|usable| (usable / 4).clamp(OPENCODE_PRESERVE_RECENT_MIN_TOKENS, OPENCODE_PRESERVE_RECENT_MAX_TOKENS))
        .unwrap_or(OPENCODE_PRESERVE_RECENT_MAX_TOKENS)
}

fn reasoning_effort(config: &super::llm::LlmConfig) -> Result<Option<&str>, LlmCallError> {
    let Some(effort) = config.reasoning_effort.as_deref() else {
        return Ok(None);
    };
    let model = config.model.to_ascii_lowercase();
    let supported: &[&str] = if model.contains("gpt-5.6") {
        &["none", "low", "medium", "high", "xhigh", "max"]
    } else if model.contains("gpt-5.5") {
        &["none", "low", "medium", "high", "xhigh"]
    } else if model.contains("fable")
        || model.contains("opus-4.7")
        || model.contains("opus-4-7")
        || model.contains("opus-4.8")
        || model.contains("opus-4-8")
        || model.contains("opus-latest")
    {
        &["low", "medium", "high", "xhigh", "max"]
    } else if model.contains("opus-4.6") || model.contains("opus-4-6") {
        &["low", "medium", "high", "max"]
    } else if config.provider == "openai" {
        &["none", "minimal", "low", "medium", "high", "xhigh"]
    } else {
        &["low", "medium", "high", "max"]
    };
    if supported.contains(&effort) {
        Ok(Some(effort))
    } else {
        Err(LlmCallError::Permanent {
            reason: format!("model {} does not support reasoning effort {effort}; supported: {}", config.model, supported.join(", ")),
            detail: None,
        })
    }
}

fn apply_anthropic_reasoning(body: &mut Value, config: &super::llm::LlmConfig, effort: &str) {
    let model = config.model.to_ascii_lowercase();
    let adaptive = model.contains("fable")
        || model.contains("opus-4.6")
        || model.contains("opus-4-6")
        || model.contains("opus-4.7")
        || model.contains("opus-4-7")
        || model.contains("opus-4.8")
        || model.contains("opus-4-8")
        || model.contains("opus-latest");
    if adaptive {
        let summarized = model.contains("fable")
            || model.contains("opus-4.7")
            || model.contains("opus-4-7")
            || model.contains("opus-4.8")
            || model.contains("opus-4-8")
            || model.contains("opus-latest");
        body["thinking"] = if summarized {
            json!({ "type": "adaptive", "display": "summarized" })
        } else {
            json!({ "type": "adaptive" })
        };
        body["output_config"] = json!({ "effort": effort });
        return;
    }
    let output = output_budget_for_request(config);
    let budget = match effort {
        "low" => (output / 8).max(1_024),
        "medium" => (output / 4).max(2_048),
        "high" => (output / 2).min(16_000),
        "xhigh" | "max" => output.saturating_sub(1).min(31_999),
        _ => return,
    };
    body["thinking"] = json!({ "type": "enabled", "budget_tokens": budget });
}

fn estimate_json_tokens(text: &str) -> u64 {
    let mut ascii = 0u64;
    let mut non_ascii = 0u64;
    for character in text.chars() {
        if character.is_ascii() {
            ascii += 1;
        } else {
            non_ascii += 1;
        }
    }
    ascii.div_ceil(4).saturating_add(non_ascii)
}

fn estimate_request_tokens(
    config: &super::llm::LlmConfig,
    messages: &[Value],
    tools: &[AiTool],
    max_output_tokens: Option<u32>,
) -> u64 {
    prepare_llm_request(config, messages, tools, max_output_tokens)
        .map(|request| estimate_json_tokens(&request.body_json))
        .unwrap_or(0)
}
const PRUNE_PROTECT_TOKENS: usize = 40_000;
const PRUNE_MINIMUM_TOKENS: usize = 20_000;

fn compaction_kind(message: &Value) -> Option<&str> {
    message.pointer("/_guardmeta/kind").and_then(Value::as_str)
}

fn compaction_split(
    messages: &[Value],
    estimated_tokens: u64,
    usable_tokens: Option<u64>,
    force: bool,
    preserve_tokens: u64,
) -> Option<usize> {
    if !force {
        match usable_tokens {
            Some(limit) if estimated_tokens >= limit => {}
            _ => return None,
        }
    }
    let first_conversation = messages.iter().position(|message| {
        message.get("role").and_then(Value::as_str) != Some("system")
    })?;
    let user_starts: Vec<usize> = messages.iter()
        .enumerate()
        .filter(|(_, message)| message.get("role").and_then(Value::as_str) == Some("user"))
        .map(|(index, _)| index)
        .collect();
    let mut split = if user_starts.len() > CONTEXT_COMPACTION_KEEP_TURNS {
        user_starts[user_starts.len() - CONTEXT_COMPACTION_KEEP_TURNS]
    } else if messages.len() > first_conversation + 1 {
        let mut suffix_tokens = 0u64;
        let mut candidate = messages.len();
        for index in (first_conversation..messages.len()).rev() {
            suffix_tokens = suffix_tokens.saturating_add(estimate_json_tokens(&messages[index].to_string()));
            if suffix_tokens > preserve_tokens {
                candidate = index.saturating_add(1);
                break;
            }
            candidate = index;
        }
        candidate
    } else {
        first_conversation
    };
    let mut tail_tokens = messages[split..].iter()
        .map(|message| estimate_json_tokens(&message.to_string()))
        .sum::<u64>();
    while split < messages.len() && tail_tokens > preserve_tokens {
        tail_tokens = tail_tokens.saturating_sub(estimate_json_tokens(&messages[split].to_string()));
        split += 1;
    }
    if split <= first_conversation {
        return None;
    }
    if messages.get(split).and_then(|message| message.get("role")).and_then(Value::as_str) == Some("tool") {
        while split > first_conversation
            && messages.get(split).and_then(|message| message.get("role")).and_then(Value::as_str) == Some("tool")
        {
            split -= 1;
        }
        if messages.get(split).and_then(|message| message.get("role")).and_then(Value::as_str) != Some("assistant") {
            return None;
        }
    }
    let compactable = messages[first_conversation..split].iter().any(|message| {
        message.get("role").and_then(Value::as_str) != Some("system")
    });
    compactable.then_some(split)
}

fn truncate_compaction_text(text: &str) -> String {
    let count = text.chars().count();
    if count <= COMPACTION_TOOL_OUTPUT_MAX_CHARS {
        return text.to_string();
    }
    let prefix: String = text.chars().take(COMPACTION_TOOL_OUTPUT_MAX_CHARS).collect();
    format!("{prefix}\n[Tool output truncated for compaction: omitted {} chars]", count - COMPACTION_TOOL_OUTPUT_MAX_CHARS)
}

fn serialize_compaction_history(messages: &[Value]) -> String {
    messages.iter().filter_map(|message| {
        match message.get("role").and_then(Value::as_str) {
            Some("user") => Some(format!(
                "[User]: {}",
                content_text(message.get("content").unwrap_or(&Value::Null)),
            )),
            Some("assistant") => {
                let mut lines = Vec::new();
                let text = content_text(message.get("content").unwrap_or(&Value::Null));
                if !text.is_empty() {
                    lines.push(format!("[Assistant]: {text}"));
                }
                for call in canonical_tool_calls(message) {
                    lines.push(format!(
                        "[Assistant tool call]: {}({})",
                        call.pointer("/function/name").and_then(Value::as_str).unwrap_or("unknown"),
                        call.pointer("/function/arguments").and_then(Value::as_str).unwrap_or("{}"),
                    ));
                }
                (!lines.is_empty()).then(|| lines.join("\n"))
            }
            Some("tool") => Some(format!(
                "[Tool result {}]: {}",
                message.get("tool_call_id").and_then(Value::as_str).unwrap_or("unknown"),
                truncate_compaction_text(&content_text(message.get("content").unwrap_or(&Value::Null))),
            )),
            Some("system") if compaction_kind(message).is_none() => {
                Some(format!(
                    "[System update]: {}",
                    content_text(message.get("content").unwrap_or(&Value::Null)),
                ))
            }
            _ => None,
        }
    }).collect::<Vec<_>>().join("\n\n")
}

fn prune_old_tool_results(
    messages: &mut [Value],
    session: &Arc<AiSession>,
    store: &AiSessionStore,
) -> usize {
    let mut protected_tokens = 0usize;
    let mut candidate_tokens = 0usize;
    let mut user_turns = 0usize;
    let mut candidates = Vec::new();

    for index in (0..messages.len()).rev() {
        let role = messages[index].get("role").and_then(Value::as_str);
        if role == Some("user") {
            user_turns += 1;
        }
        if user_turns < 2 {
            continue;
        }
        if role == Some("system") && compaction_kind(&messages[index]) == Some("compaction") {
            break;
        }
        if role != Some("tool") {
            continue;
        }
        let content = content_text(messages[index].get("content").unwrap_or(&Value::Null));
        if content.starts_with("[Old tool result content cleared;") {
            continue;
        }
        let estimated_tokens = content.chars().count().div_ceil(4);
        protected_tokens = protected_tokens.saturating_add(estimated_tokens);
        if protected_tokens <= PRUNE_PROTECT_TOKENS {
            continue;
        }
        candidate_tokens = candidate_tokens.saturating_add(estimated_tokens);
        candidates.push((index, content));
    }

    if candidate_tokens <= PRUNE_MINIMUM_TOKENS {
        return 0;
    }

    for (index, content) in &candidates {
        let tool_call_id = messages[*index]
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let artifact_id = serde_json::from_str::<Value>(content)
            .ok()
            .and_then(|value| value.get("artifact_id").and_then(Value::as_str).map(ToString::to_string))
            .unwrap_or_else(|| {
                let data = serde_json::from_str::<Value>(content)
                    .unwrap_or_else(|_| Value::String(content.clone()));
                session.store_artifact(
                    store,
                    "pruned_tool_result",
                    format!("pruned tool result {tool_call_id}: {} bytes", content.len()),
                    content.len() as u64,
                    data,
                )
            });
        messages[*index]["content"] = Value::String(format!(
            "[Old tool result content cleared; full content saved as artifact {artifact_id}]"
        ));
    }
    candidates.len()
}

fn compaction_prompt(previous_summary: Option<&str>, history: &str) -> String {
    let instruction = previous_summary.map(|summary| format!(
        "Update the anchored summary below using the new conversation history. Preserve still-true details, remove stale details, and merge new facts.\n<previous-summary>\n{summary}\n</previous-summary>"
    )).unwrap_or_else(|| "Create a new anchored summary from the conversation history.".to_string());
    format!(r#"{instruction}

Output exactly this Markdown structure and keep every section:
## Objective
- [current user objective]

## Important Details
- [constraints, decisions, exact identifiers, debugger state, or (none)]

## Work State
### Completed
- [verified completed work or (none)]
### Active
- [current partial work or (none)]
### Blocked
- [blockers and exact errors or (none)]

## Next Move
1. [immediate concrete action]

## Relevant Files
- [path and purpose or (none)]

Rules:
- Preserve exact paths, addresses, symbols, commands, error strings, URLs, process IDs, modes, and breakpoint state.
- Do not mention the summary process or context compaction.
- Keep it concise but sufficient to continue without the replaced history.

<conversation-history>
{history}
</conversation-history>"#)
}

async fn compact_context_if_needed<F>(
    client: &reqwest::Client,
    config: &super::llm::LlmConfig,
    messages: &mut Vec<Value>,
    estimated_tokens: u64,
    force: bool,
    emit: &F,
    session: &Arc<AiSession>,
) -> bool
where
    F: Fn(&str, Value),
{
    use sha2::Digest as _;

    let Some(split) = compaction_split(
        messages,
        estimated_tokens,
        usable_input_tokens(config),
        force,
        preserve_recent_budget(config),
    ) else {
        return false;
    };
    let previous = messages.iter().find(|message| compaction_kind(message) == Some("compaction"));
    let previous_summary = previous.and_then(|message| message.get("content")).and_then(Value::as_str);
    let previous_id = previous.and_then(|message| message.pointer("/_guardmeta/id")).and_then(Value::as_str);
    let generation = previous
        .and_then(|message| message.pointer("/_guardmeta/generation"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let head: Vec<Value> = messages[..split].iter()
        .filter(|message| compaction_kind(message) != Some("base_system") && compaction_kind(message) != Some("compaction"))
        .cloned()
        .collect();
    let history = serialize_compaction_history(&head);
    if history.trim().is_empty() {
        return false;
    }
    let source_json = serde_json::to_vec(messages).unwrap_or_default();
    let source_sha256 = hex::encode(sha2::Sha256::digest(&source_json));
    let compaction_id = format!("compact-{}-{generation}", unix_time_ms());
    let started = json!({
        "kind": "compaction_started",
        "payload": {
            "id": compaction_id,
            "generation": generation,
            "previous_id": previous_id,
            "source_message_count": messages.len(),
            "source_sha256": source_sha256,
            "tail_start_index": split,
        }
    });
    let _ = append_log(&session.id, &started);
    emit("context_compaction_start", json!({
        "id": compaction_id,
        "generation": generation,
        "source_message_count": messages.len(),
        "tail_start_index": split,
        "estimated_input_tokens": estimated_tokens,
        "usable_input_tokens": usable_input_tokens(config),
        "summary_max_output_tokens": output_budget_for_request(config),
    }));

    let summary_messages = vec![
        json!({
            "role": "system",
            "content": "You are a context compaction engine. Return only the requested anchored Markdown summary.",
        }),
        json!({
            "role": "user",
            "content": compaction_prompt(previous_summary, &history),
        }),
    ];
    let empty_tools: Vec<AiTool> = Vec::new();
    let summary_result = call_with_retry(
        client,
        config,
        &summary_messages,
        &empty_tools,
        Some(output_budget_for_request(config)),
        emit,
        session,
    ).await;
    let summary = match summary_result {
        Ok((assistant, _, calls)) if calls.is_empty() => {
            content_text(assistant.get("content").unwrap_or(&Value::Null)).trim().to_string()
        }
        Ok(_) => String::new(),
        Err(error) => {
            let reason = error.reason().to_string();
            let _ = append_log(&session.id, &json!({
                "kind": "compaction_failed",
                "payload": { "id": compaction_id, "generation": generation, "reason": reason }
            }));
            emit("context_compaction_failed", json!({ "id": compaction_id, "reason": reason }));
            return false;
        }
    };
    if summary.is_empty() {
        let reason = "compaction returned an empty summary";
        let _ = append_log(&session.id, &json!({
            "kind": "compaction_failed",
            "payload": { "id": compaction_id, "generation": generation, "reason": reason }
        }));
        emit("context_compaction_failed", json!({ "id": compaction_id, "reason": reason }));
        return false;
    }

    let summary_message = json!({
        "role": "system",
        "content": summary,
        "_guardmeta": {
            "kind": "compaction",
            "id": compaction_id,
            "generation": generation,
            "previous_id": previous_id,
            "source_sha256": source_sha256,
            "covered_message_count": split,
        }
    });
    let mut active_for_storage = vec![summary_message.clone()];
    if messages.get(split).and_then(|message| message.get("role")).and_then(Value::as_str) != Some("user") {
        active_for_storage.push(json!({
            "role": "user",
            "content": "Continue from the conversation checkpoint with the retained recent execution trace.",
            "_guardmeta": { "kind": "compaction_continue" },
        }));
    }
    active_for_storage.extend(messages[split..].iter().cloned());
    let commit = json!({
        "kind": "compaction_commit",
        "payload": {
            "id": compaction_id,
            "generation": generation,
            "previous_id": previous_id,
            "source_message_count": messages.len(),
            "source_sha256": source_sha256,
            "covered_message_count": split,
            "tail_start_index": split,
            "active_messages": active_for_storage,
        }
    });
    if let Err(error) = append_log_durable(&session.id, &commit) {
        emit("context_compaction_failed", json!({
            "id": compaction_id,
            "reason": format!("persist compaction commit: {error}"),
        }));
        return false;
    }

    let mut next = vec![json!({
        "role": "system",
        "content": system_prompt(),
        "_guardmeta": { "kind": "base_system" },
    })];
    next.extend(active_for_storage.iter().cloned());
    *messages = repair_tool_transactions(next);
    emit("context_compacted", json!({
        "id": compaction_id,
        "generation": generation,
        "covered_message_count": split,
        "messages": active_for_storage,
    }));
    true
}

#[derive(Debug, Deserialize)]
pub struct AiRunReq {
    pub session_id: String,
    pub config: super::llm::LlmConfig,
    /// 完整 history (前端维护)
    pub messages: Vec<Value>,
    pub display_messages: Option<Vec<Value>>,
    pub enabled_tools: Option<Vec<String>>,
    pub max_rounds: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AiRunResp {
    pub rounds: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub total_tokens: u64,
    pub truncated: bool,
    pub cancelled: bool,
    pub completed: bool,
    pub final_summary: Option<String>,
}

/// 流式 agent 入口. 不返完整 new_messages — 全部走 Event Emit.
///
/// 事件:
///   ai-run::{session_id}  payload = { kind: "..." , data: ... }
///     kinds:
///       round_start    { round }
///       assistant      { message }      — LLM 的回包
///       tool_start     { id, name, args }
///       tool_done      { id, name, result }
///       tool_message   { message }      — 协议形式的回灌消息 (前端 append)
///       error          { stage, error }
///       complete       { summary, cancelled, truncated }
#[tauri::command]
pub async fn dbg_ai_run(
    app: AppHandle,
    store: State<'_, Arc<AiSessionStore>>,
    req: AiRunReq,
) -> AppResult<AiRunResp> {
    use tauri::Emitter;
    let store_arc = store.inner().clone();
    let session = store_arc.get_or_create(&req.session_id);
    session.reset_cancel();

    let max_rounds = req.max_rounds.unwrap_or(200).clamp(1, 256);
    let mut tools = filter_tools(req.enabled_tools.as_deref());
    // P115: 合并所有 connected MCP server 的工具
    {
        use tauri::Manager;
        let reg = app.state::<Arc<McpRegistry>>();
        append_mcp_tools(reg.inner(), &mut tools).await;
    }
    let tools = tools;

    let mut messages = normalize_provider_history(&req.messages);
    ensure_guardmeta_system_prompt(&mut messages);

    let event_name = format!("ai-run::{}", req.session_id);
    let emit = |kind: &str, data: Value| {
        let _ = app.emit(&event_name, json!({ "kind": kind, "data": data }));
    };

    let snapshot_messages: Vec<Value> = messages.iter()
        .filter(|message| compaction_kind(message) != Some("base_system"))
        .cloned()
        .collect();
    let display_snapshot = req.display_messages.as_deref()
        .map(normalize_provider_history)
        .unwrap_or_else(|| snapshot_messages.clone());
    let snapshot_created = match ensure_history_snapshot(&req.session_id, &snapshot_messages, &display_snapshot) {
        Ok(created) => created,
        Err(error) => {
            emit("context_persistence_warning", json!({ "error": error.to_string() }));
            false
        }
    };
    // The first durable snapshot already contains this turn's user message.
    if !snapshot_created {
        if let Some(last_user) = messages.iter().rev().find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user")) {
            let _ = append_log(&req.session_id, &json!({ "kind": "user", "payload": last_user }));
        }
    }

    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut total_cache_read = 0u64;
    let mut total_cache_write = 0u64;
    let mut total_context_tokens = 0u64;
    let mut rounds = 0u32;
    let mut truncated = false;
    let mut completed = false;
    let mut final_summary: Option<String> = None;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .map_err(|e| AppError::Internal(format!("reqwest build: {e}")))?;
    let mut observed_context_tokens: Option<u64> = None;

    loop {
        if session.is_cancelled() {
            emit("complete", json!({ "cancelled": true, "rounds": rounds }));
            break;
        }
        if rounds >= max_rounds { truncated = true; emit("complete", json!({"truncated":true,"rounds":rounds})); break; }

        let before_prune = messages.clone();
        let pruned_count = prune_old_tool_results(&mut messages, &session, &store_arc);
        if pruned_count > 0 {
            let visible_messages: Vec<Value> = messages.iter()
                .filter(|message| compaction_kind(message) != Some("base_system"))
                .cloned()
                .collect();
            let prune_record = json!({
                "kind": "tool_prune_commit",
                "payload": {
                    "pruned_count": pruned_count,
                    "active_messages": visible_messages,
                }
            });
            if let Err(error) = append_log_durable(&req.session_id, &prune_record) {
                messages = before_prune;
                emit("context_persistence_warning", json!({
                    "stage": "tool_prune",
                    "error": error.to_string(),
                }));
            } else {
                emit("context_pruned", json!({
                    "count": pruned_count,
                    "messages": visible_messages,
                }));
            }
        }

        let request_output_tokens = max_output_tokens(&req.config);
        let estimated_tokens = estimate_request_tokens(&req.config, &messages, &tools, request_output_tokens);
        let usable_tokens = usable_input_tokens(&req.config);
        let observed_overflow = observed_context_tokens
            .zip(usable_tokens)
            .is_some_and(|(observed, usable)| observed >= usable);
        let estimated_overflow = usable_tokens
            .is_some_and(|usable| estimated_tokens > 0 && estimated_tokens >= usable);
        if observed_overflow || estimated_overflow {
            let _ = compact_context_if_needed(
                &client,
                &req.config,
                &mut messages,
                estimated_tokens,
                observed_overflow,
                &emit,
                &session,
            ).await;
            if session.is_cancelled() {
                emit("complete", json!({ "cancelled": true, "rounds": rounds }));
                break;
            }
        }

        emit("round_start", json!({ "round": rounds }));

        // 带重试调 LLM. 5xx/429/网络错 → 指数退避. 4xx → 立即放弃.
        let mut overflow_recovery_attempted = false;
        let llm_res = loop {
            let result = call_with_retry(
            &client,
            &req.config,
            &messages,
            &tools,
            request_output_tokens,
            &emit,
            &session,
            ).await;
            match result {
                Err(error) if error.is_context_overflow() && !overflow_recovery_attempted => {
                    overflow_recovery_attempted = true;
                    emit("context_overflow", json!({
                        "reason": error.reason(),
                        "estimated_input_tokens": estimated_tokens,
                        "usable_input_tokens": usable_tokens,
                    }));
                    if compact_context_if_needed(
                        &client,
                        &req.config,
                        &mut messages,
                        estimated_tokens,
                        true,
                        &emit,
                        &session,
                    ).await {
                        continue;
                    }
                    break Err(error);
                }
                other => break other,
            }
        };
        let (assistant_msg, usage, tool_calls) = match llm_res {
            Ok((assistant, usage, calls)) => {
                observed_context_tokens = Some(usage.context_tokens());
                (assistant, usage, calls)
            }
            Err(e) => {
                let err_str = match &e {
                    LlmCallError::Retryable { reason, .. }
                    | LlmCallError::Permanent { reason, .. }
                    | LlmCallError::ContextOverflow { reason, .. } => reason.clone(),
                };
                emit("error", json!({ "stage": "llm_call", "error": err_str }));
                emit("complete", json!({ "error": err_str, "rounds": rounds }));
                return Err(e.into_app_err());
            }
        };

        total_in = total_in.saturating_add(usage.input);
        total_out = total_out.saturating_add(usage.output);
        total_cache_read = total_cache_read.saturating_add(usage.cache_read);
        total_cache_write = total_cache_write.saturating_add(usage.cache_write);
        total_context_tokens = total_context_tokens.saturating_add(usage.context_tokens());

        messages.push(assistant_msg.clone());
        let _ = append_log(&req.session_id, &json!({
            "kind": "assistant",
            "payload": assistant_msg.clone(),
            "usage": usage,
        }));
        emit("assistant", json!({
            "message": assistant_msg,
            "in": usage.input,
            "out": usage.output,
            "cache_read": usage.cache_read,
            "cache_write": usage.cache_write,
            "total": usage.context_tokens(),
        }));

        if tool_calls.is_empty() {
            // LLM 没调工具 → 自然终止
            completed = true;
            emit("complete", json!({ "rounds": rounds, "natural": true }));
            break;
        }

        rounds += 1;

        // 分串行 / 并行
        let mut serial_calls = Vec::new();
        let mut parallel_calls = Vec::new();
        let serial_names: std::collections::HashSet<String> = tools.iter()
            .filter(|t| t.serial).map(|t| t.name.to_string()).collect();
        for tc in tool_calls {
            if serial_names.contains(&tc.name) {
                serial_calls.push(tc);
            } else {
                parallel_calls.push(tc);
            }
        }

        // 并行执行 parallel_calls
        let mut results: Vec<(String, String, DispatchResult)> = Vec::new();
        // 串行处理 serial 优先(scan_first→next 顺序很重要)
        for tc in serial_calls {
            if session.is_cancelled() { break; }
            emit("tool_start", json!({ "id": tc.id, "name": tc.name, "args": tc.input }));
            let r = dispatch_tool(&tc.name, &tc.input, &app, &session, &store_arc).await;
            let v_for_event = match &r {
                DispatchResult::Value(v) => v.clone(),
                DispatchResult::Done(s) => json!({ "completed": true, "summary": s }),
            };
            emit("tool_done", json!({ "id": tc.id, "name": tc.name, "result": v_for_event }));
            results.push((tc.id, tc.name, r));
        }
        if !parallel_calls.is_empty() && !session.is_cancelled() {
            let futs: Vec<_> = parallel_calls.into_iter().map(|tc| {
                let app2 = app.clone();
                let session2 = session.clone();
                let store2 = store_arc.clone();
                let ev = event_name.clone();
                let app3 = app.clone();
                async move {
                    let _ = app3.emit(&ev, json!({"kind":"tool_start","data":{"id": tc.id, "name": tc.name, "args": tc.input}}));
                    let r = dispatch_tool(&tc.name, &tc.input, &app2, &session2, &store2).await;
                    let v_for_event = match &r {
                        DispatchResult::Value(v) => v.clone(),
                        DispatchResult::Done(s) => json!({ "completed": true, "summary": s }),
                    };
                    let _ = app3.emit(&ev, json!({"kind":"tool_done","data":{"id": tc.id.clone(), "name": tc.name.clone(), "result": v_for_event}}));
                    (tc.id, tc.name, r)
                }
            }).collect();
            let par_results = futures_util::future::join_all(futs).await;
            results.extend(par_results);
        }

        // 处理结果, 看是否有 Done
        let mut done_summary: Option<String> = None;
        let mut tool_value_pairs: Vec<(String, Value)> = Vec::new();
        for (id, name, r) in results {
            match r {
                DispatchResult::Done(s) => {
                    done_summary = Some(s.clone());
                    tool_value_pairs.push((id, json!({ "ok": true, "completed": true, "summary": s })));
                }
                DispatchResult::Value(v) => tool_value_pairs.push((
                    id,
                    tool_result_for_context(&name, v, &session, &store_arc),
                )),
            }
        }

        // Internal history always uses the provider-neutral canonical tool message.
        for (id, result) in tool_value_pairs {
            let m = json!({
                "role": "tool",
                "tool_call_id": id,
                "content": result.to_string(),
            });
            messages.push(m.clone());
            let _ = append_log(&req.session_id, &json!({ "kind": "tool_result", "payload": m }));
            emit("tool_message", json!({ "message": m }));
        }

        if let Some(s) = done_summary {
            completed = true;
            final_summary = Some(s.clone());
            let _ = append_log(&req.session_id, &json!({ "kind": "complete", "payload": { "summary": s } }));
            emit("complete", json!({ "summary": s, "rounds": rounds, "natural": false }));
            break;
        }
    }

    Ok(AiRunResp {
        rounds,
        input_tokens: total_in,
        output_tokens: total_out,
        cache_read_tokens: total_cache_read,
        cache_write_tokens: total_cache_write,
        total_tokens: total_context_tokens,
        truncated,
        cancelled: session.is_cancelled(),
        completed,
        final_summary,
    })
}

#[tauri::command]
pub fn dbg_ai_cancel(store: State<'_, Arc<AiSessionStore>>, session_id: String) -> AppResult<()> {
    store.cancel(&session_id);
    Ok(())
}

#[tauri::command]
pub fn dbg_ai_session_list() -> AppResult<Vec<SessionFileInfo>> {
    list_sessions().map_err(|e| AppError::Internal(format!("list: {e}")))
}

#[tauri::command]
pub fn dbg_ai_session_load(session_id: String) -> AppResult<Value> {
    let context = load_session(&session_id)
        .map(|messages| normalize_provider_history(&messages))
        .map_err(|e| AppError::Internal(format!("load context: {e}")))?;
    let history = load_session_history(&session_id)
        .map(|messages| normalize_provider_history(&messages))
        .map_err(|e| AppError::Internal(format!("load history: {e}")))?;
    Ok(json!({ "history": history, "context": context }))
}

#[tauri::command]
pub fn dbg_ai_session_delete(session_id: String) -> AppResult<()> {
    delete_session(&session_id).map_err(|e| AppError::Internal(format!("delete: {e}")))
}

#[tauri::command]
pub async fn dbg_ai_tools_describe(
    registry: State<'_, Arc<McpRegistry>>,
) -> AppResult<Vec<AiTool>> {
    let mut t = tool_table();
    append_mcp_tools(registry.inner(), &mut t).await;
    Ok(t)
}


// ===== OpenAI =====

#[derive(Debug, Clone)]
struct ToolCallParsed {
    id: String,
    name: String,
    input: Value,
}

#[derive(Debug)]
struct PreparedLlmRequest {
    provider: String,
    model: String,
    url: String,
    headers_for_log: Vec<(String, String)>,
    body_json: String,
    message_count: usize,
    tool_count: usize,
}

// BEGIN TEMP_AI_TRANSPORT_DIAGNOSTICS: remove this diagnostic-only block before production release.
#[derive(Debug)]
struct LlmFailureDetail {
    phase: &'static str,
    started_unix_ms: u128,
    elapsed_to_headers_ms: Option<u128>,
    elapsed_total_ms: u128,
    response_status: Option<u16>,
    response_headers: Vec<(String, String)>,
    response_body: Option<String>,
    transport_error: Option<String>,
}
// END TEMP_AI_TRANSPORT_DIAGNOSTICS

fn trim_url(s: &str) -> String {
    let mut t = s.trim().trim_end_matches('/').to_string();
    if !t.starts_with("http://") && !t.starts_with("https://") {
        t = format!("https://{}", t);
    }
    t
}

fn content_text(content: &Value) -> String {
    match content {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts.iter()
            .filter_map(|part| {
                if let Some(text) = part.as_str() {
                    return Some(text.to_string());
                }
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

fn canonical_tool_call(id: &str, name: &str, arguments: &Value) -> Option<Value> {
    if id.is_empty() || name.is_empty() {
        return None;
    }
    let arguments = arguments.as_str()
        .map(ToString::to_string)
        .unwrap_or_else(|| arguments.to_string());
    Some(json!({
        "id": id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": arguments,
        }
    }))
}

fn canonical_tool_calls(message: &Value) -> Vec<Value> {
    message.get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|call| {
            canonical_tool_call(
                call.get("id").and_then(Value::as_str).unwrap_or(""),
                call.pointer("/function/name").and_then(Value::as_str).unwrap_or(""),
                call.pointer("/function/arguments").unwrap_or(&Value::Null),
            )
        })
        .collect()
}

fn canonical_message(role: &str, content: Value, metadata: Option<&Value>) -> Value {
    let mut message = json!({ "role": role, "content": content });
    if let Some(metadata) = metadata {
        message["_guardmeta"] = metadata.clone();
    }
    message
}

fn normalize_provider_history(input: &[Value]) -> Vec<Value> {
    let mut normalized = Vec::new();
    for message in input {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        let metadata = message.get("_guardmeta");
        match role {
            "system" => {
                normalized.push(canonical_message(
                    "system",
                    Value::String(content_text(message.get("content").unwrap_or(&Value::Null))),
                    metadata,
                ));
            }
            "user" => {
                let content = message.get("content").unwrap_or(&Value::Null);
                if let Some(parts) = content.as_array() {
                    let mut text = Vec::new();
                    for part in parts {
                        match part.get("type").and_then(Value::as_str) {
                            Some("tool_result") => {
                                let id = part.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
                                if !id.is_empty() {
                                    normalized.push(json!({
                                        "role": "tool",
                                        "tool_call_id": id,
                                        "content": content_text(part.get("content").unwrap_or(&Value::Null)),
                                    }));
                                }
                            }
                            Some("text") => {
                                if let Some(value) = part.get("text").and_then(Value::as_str) {
                                    text.push(value.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                    if !text.is_empty() {
                        normalized.push(canonical_message(
                            "user",
                            Value::String(text.join("\n")),
                            metadata,
                        ));
                    }
                } else {
                    normalized.push(canonical_message(
                        "user",
                        Value::String(content_text(content)),
                        metadata,
                    ));
                }
            }
            "assistant" => {
                let content = message.get("content").unwrap_or(&Value::Null);
                let mut text = content.as_str().map(ToString::to_string).unwrap_or_default();
                let mut calls = canonical_tool_calls(message);
                if let Some(parts) = content.as_array() {
                    let mut text_parts = Vec::new();
                    for part in parts {
                        match part.get("type").and_then(Value::as_str) {
                            Some("text") => {
                                if let Some(value) = part.get("text").and_then(Value::as_str) {
                                    text_parts.push(value.to_string());
                                }
                            }
                            Some("tool_use") => {
                                if let Some(call) = canonical_tool_call(
                                    part.get("id").and_then(Value::as_str).unwrap_or(""),
                                    part.get("name").and_then(Value::as_str).unwrap_or(""),
                                    part.get("input").unwrap_or(&Value::Null),
                                ) {
                                    calls.push(call);
                                }
                            }
                            _ => {}
                        }
                    }
                    text = text_parts.join("\n");
                }
                let mut canonical = canonical_message(
                    "assistant",
                    if text.is_empty() { Value::Null } else { Value::String(text) },
                    metadata,
                );
                if !calls.is_empty() {
                    canonical["tool_calls"] = Value::Array(calls);
                }
                normalized.push(canonical);
            }
            "tool" => {
                let id = message.get("tool_call_id").and_then(Value::as_str).unwrap_or("");
                if !id.is_empty() {
                    normalized.push(json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "content": content_text(message.get("content").unwrap_or(&Value::Null)),
                    }));
                }
            }
            _ => {}
        }
    }
    repair_tool_transactions(normalized)
}

fn repair_tool_transactions(messages: Vec<Value>) -> Vec<Value> {
    let mut repaired = Vec::new();
    let mut index = 0usize;
    while index < messages.len() {
        let message = &messages[index];
        let calls = canonical_tool_calls(message);
        if message.get("role").and_then(Value::as_str) == Some("assistant") && !calls.is_empty() {
            let expected: std::collections::HashSet<String> = calls.iter()
                .filter_map(|call| call.get("id").and_then(Value::as_str).map(ToString::to_string))
                .collect();
            let mut found = std::collections::HashSet::new();
            let mut end = index + 1;
            while end < messages.len() && messages[end].get("role").and_then(Value::as_str) == Some("tool") {
                if let Some(id) = messages[end].get("tool_call_id").and_then(Value::as_str) {
                    found.insert(id.to_string());
                }
                end += 1;
            }
            if expected == found && expected.len() == end.saturating_sub(index + 1) {
                repaired.extend(messages[index..end].iter().cloned());
            } else if !content_text(message.get("content").unwrap_or(&Value::Null)).trim().is_empty() {
                let mut text_only = message.clone();
                if let Some(object) = text_only.as_object_mut() {
                    object.remove("tool_calls");
                }
                repaired.push(text_only);
            }
            index = end;
            continue;
        }
        if message.get("role").and_then(Value::as_str) != Some("tool") {
            repaired.push(message.clone());
        }
        index += 1;
    }
    repaired
}

fn openai_wire_messages(messages: &[Value]) -> Vec<Value> {
    messages.iter().filter_map(|message| {
        match message.get("role").and_then(Value::as_str) {
            Some("system") | Some("user") => Some(json!({
                "role": message.get("role").cloned().unwrap_or(Value::Null),
                "content": content_text(message.get("content").unwrap_or(&Value::Null)),
            })),
            Some("assistant") => {
                let calls = canonical_tool_calls(message);
                let text = content_text(message.get("content").unwrap_or(&Value::Null));
                if calls.is_empty() && text.is_empty() {
                    return None;
                }
                let mut wire = json!({
                    "role": "assistant",
                    "content": if text.is_empty() { Value::Null } else { Value::String(text) },
                });
                if !calls.is_empty() {
                    wire["tool_calls"] = Value::Array(calls);
                }
                Some(wire)
            }
            Some("tool") => Some(json!({
                "role": "tool",
                "tool_call_id": message.get("tool_call_id").cloned().unwrap_or(Value::Null),
                "content": content_text(message.get("content").unwrap_or(&Value::Null)),
            })),
            _ => None,
        }
    }).collect()
}

fn anthropic_blocks(content: Value) -> Vec<Value> {
    match content {
        Value::Array(parts) => parts,
        Value::String(text) if !text.is_empty() => vec![json!({ "type": "text", "text": text })],
        _ => Vec::new(),
    }
}

fn push_anthropic_turn(turns: &mut Vec<Value>, role: &str, content: Value) {
    let incoming = anthropic_blocks(content);
    if incoming.is_empty() {
        return;
    }
    if let Some(last) = turns.last_mut() {
        if last.get("role").and_then(Value::as_str) == Some(role) {
            let previous = last.get_mut("content").map(std::mem::take).unwrap_or(Value::Null);
            let mut merged = anthropic_blocks(previous);
            merged.extend(incoming);
            last["content"] = Value::Array(merged);
            return;
        }
    }
    turns.push(json!({ "role": role, "content": incoming }));
}

fn anthropic_wire_messages(messages: &[Value]) -> (String, Vec<Value>) {
    let mut system = Vec::new();
    let mut turns = Vec::new();
    for message in messages {
        match message.get("role").and_then(Value::as_str) {
            Some("system") => {
                let text = content_text(message.get("content").unwrap_or(&Value::Null));
                if !text.is_empty() {
                    system.push(text);
                }
            }
            Some("user") => {
                push_anthropic_turn(
                    &mut turns,
                    "user",
                    Value::String(content_text(message.get("content").unwrap_or(&Value::Null))),
                );
            }
            Some("assistant") => {
                let mut blocks = Vec::new();
                let text = content_text(message.get("content").unwrap_or(&Value::Null));
                if !text.is_empty() {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
                for call in canonical_tool_calls(message) {
                    let arguments = call.pointer("/function/arguments")
                        .and_then(Value::as_str)
                        .and_then(|value| serde_json::from_str::<Value>(value).ok())
                        .unwrap_or_else(|| json!({}));
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": call.get("id").cloned().unwrap_or(Value::Null),
                        "name": call.pointer("/function/name").cloned().unwrap_or(Value::Null),
                        "input": arguments,
                    }));
                }
                push_anthropic_turn(&mut turns, "assistant", Value::Array(blocks));
            }
            Some("tool") => {
                push_anthropic_turn(&mut turns, "user", Value::Array(vec![json!({
                    "type": "tool_result",
                    "tool_use_id": message.get("tool_call_id").cloned().unwrap_or(Value::Null),
                    "content": content_text(message.get("content").unwrap_or(&Value::Null)),
                })]));
            }
            _ => {}
        }
    }
    (system.join("\n\n"), turns)
}

fn ensure_guardmeta_system_prompt(messages: &mut Vec<Value>) {
    messages.retain(|message| {
        !(message.get("role").and_then(Value::as_str) == Some("system")
            && message.get("content").and_then(Value::as_str) == Some(system_prompt()))
    });
    messages.insert(0, json!({
        "role": "system",
        "content": system_prompt(),
        "_guardmeta": { "kind": "base_system" },
    }));
}

/// LLM 调用错误分类
#[derive(Debug)]
enum LlmCallError {
    /// 临时错误 — 应重试 (5xx, 429, 连接错, 超时, body 读失败)
    Retryable {
        reason: String,
        /// HTTP 状态码 (若有). 用于读 retry-after.
        status: Option<u16>,
        /// 显式 retry-after 秒数 (429 头里).
        retry_after_secs: Option<u64>,
        detail: Option<Box<LlmFailureDetail>>,
    },
    /// 永久错误 — 4xx 业务错 / 协议解析失败 — 不重试, 直接抛出
    Permanent {
        reason: String,
        detail: Option<Box<LlmFailureDetail>>,
    },
    ContextOverflow {
        reason: String,
        detail: Option<Box<LlmFailureDetail>>,
    },
}

impl LlmCallError {
    fn into_app_err(self) -> AppError {
        match self {
            LlmCallError::Retryable { reason, .. }
            | LlmCallError::Permanent { reason, .. }
            | LlmCallError::ContextOverflow { reason, .. } => {
                AppError::Internal(reason)
            }
        }
    }

    fn reason(&self) -> &str {
        match self {
            LlmCallError::Retryable { reason, .. }
            | LlmCallError::Permanent { reason, .. }
            | LlmCallError::ContextOverflow { reason, .. } => reason,
        }
    }

    fn status(&self) -> Option<u16> {
        match self {
            LlmCallError::Retryable { status, .. } => *status,
            LlmCallError::Permanent { detail, .. } => {
                detail.as_ref().and_then(|detail| detail.response_status)
            }
            LlmCallError::ContextOverflow { detail, .. } => {
                detail.as_ref().and_then(|detail| detail.response_status)
            }
        }
    }

    fn retry_after_secs(&self) -> Option<u64> {
        match self {
            LlmCallError::Retryable { retry_after_secs, .. } => *retry_after_secs,
            LlmCallError::Permanent { .. } | LlmCallError::ContextOverflow { .. } => None,
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(self, LlmCallError::Retryable { .. })
    }

    fn detail(&self) -> Option<&LlmFailureDetail> {
        match self {
            LlmCallError::Retryable { detail, .. }
            | LlmCallError::Permanent { detail, .. }
            | LlmCallError::ContextOverflow { detail, .. } => {
                detail.as_deref()
            }
        }
    }

    fn is_context_overflow(&self) -> bool {
        matches!(self, LlmCallError::ContextOverflow { .. })
    }
}

fn is_context_overflow_body(status: reqwest::StatusCode, body: &str) -> bool {
    if status.as_u16() == 413 || (status.as_u16() == 400 && body.trim().is_empty()) {
        return true;
    }
    let lower = body.to_ascii_lowercase();
    [
        "context_length_exceeded",
        "prompt is too long",
        "input is too long",
        "exceeds the context window",
        "maximum context length",
        "maximum prompt length",
        "reduce the length of the messages",
        "request entity too large",
        "context window exceeds",
        "exceeded model token limit",
        "tokens in request more than max tokens allowed",
        "greater than the context length",
        "model_context_window_exceeded",
    ].iter().any(|needle| lower.contains(needle))
}

/// 判定 HTTP status 是不是值得重试的
fn classify_http_err(
    status: reqwest::StatusCode,
    body: &str,
    retry_after: Option<u64>,
    detail: LlmFailureDetail,
) -> LlmCallError {
    let code = status.as_u16();
    let reason = format!("HTTP {}: {}", status, body.chars().take(500).collect::<String>());
    if is_context_overflow_body(status, body) {
        return LlmCallError::ContextOverflow {
            reason,
            detail: Some(Box::new(detail)),
        };
    }
    // 重试: 5xx, 429, 408 timeout, 上游网关错
    if code == 408 || code == 425 || code == 429 || (500..=599).contains(&code) {
        LlmCallError::Retryable {
            reason,
            status: Some(code),
            retry_after_secs: retry_after,
            detail: Some(Box::new(detail)),
        }
    } else {
        // 401/403/400 等 — 不重试
        LlmCallError::Permanent {
            reason,
            detail: Some(Box::new(detail)),
        }
    }
}

fn classify_send_err(
    e: reqwest::Error,
    started_unix_ms: u128,
    elapsed_total_ms: u128,
) -> LlmCallError {
    // 连接错 / 超时 / DNS / TLS 握手等 — 全部 retryable
    let transport_error = format!(
        "{e:#?}\nis_timeout={}\nis_connect={}\nis_request={}\nis_body={}\nis_decode={}",
        e.is_timeout(),
        e.is_connect(),
        e.is_request(),
        e.is_body(),
        e.is_decode(),
    );
    LlmCallError::Retryable {
        reason: format!("HTTP send: {e}"),
        status: None,
        retry_after_secs: None,
        detail: Some(Box::new(LlmFailureDetail {
            phase: "send_or_wait_headers",
            started_unix_ms,
            elapsed_to_headers_ms: None,
            elapsed_total_ms,
            response_status: None,
            response_headers: Vec::new(),
            response_body: None,
            transport_error: Some(transport_error),
        })),
    }
}

/// 重试上限 + 退避基数 (毫秒). 第 N 次重试等 base * 2^(N-1), 上限 30s.
fn unix_time_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn prepare_llm_request(
    config: &super::llm::LlmConfig,
    messages: &[Value],
    tools: &[AiTool],
    max_output_tokens: Option<u32>,
) -> Result<PreparedLlmRequest, LlmCallError> {
    let effort = reasoning_effort(config)?;
    let (url, headers_for_log, body) = match config.provider.as_str() {
        "openai" => {
            let tool_decls: Vec<Value> = tools.iter().map(|tool| json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                }
            })).collect();
            let mut body = json!({
                "model": config.model,
                "messages": openai_wire_messages(messages),
                "tools": tool_decls,
            });
            if effort.is_none() {
                body["temperature"] = json!(config.temperature.unwrap_or(0.2));
            }
            if let Some(effort) = effort {
                body["reasoning_effort"] = json!(effort);
            }
            if let Some(max_output_tokens) = max_output_tokens {
                body["max_tokens"] = json!(max_output_tokens);
            }
            (
                format!("{}/chat/completions", trim_url(&config.base_url)),
                vec![
                    ("authorization".to_string(), "Bearer <redacted>".to_string()),
                    ("content-type".to_string(), "application/json".to_string()),
                ],
                body,
            )
        }
        "anthropic" => {
            let (system, turns) = anthropic_wire_messages(messages);
            let tool_decls: Vec<Value> = tools.iter().map(|tool| json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })).collect();
            let mut body = json!({
                "model": config.model,
                "messages": turns,
                "tools": tool_decls,
                "max_tokens": max_output_tokens.unwrap_or_else(|| {
                    if config.provider == "anthropic" {
                        ANTHROPIC_FALLBACK_OUTPUT_TOKENS
                    } else {
                        OPENCODE_OUTPUT_TOKEN_MAX
                    }
                }),
                "temperature": config.temperature.unwrap_or(0.2),
            });
            if !system.is_empty() {
                body["system"] = Value::String(system);
            }
            if let Some(effort) = effort {
                apply_anthropic_reasoning(&mut body, config, effort);
                if let Some(object) = body.as_object_mut() {
                    object.remove("temperature");
                }
            }
            (
                format!("{}/messages", trim_url(&config.base_url)),
                vec![
                    ("x-api-key".to_string(), "<redacted>".to_string()),
                    ("anthropic-version".to_string(), "2023-06-01".to_string()),
                    ("content-type".to_string(), "application/json".to_string()),
                ],
                body,
            )
        }
        other => {
            return Err(LlmCallError::Permanent {
                reason: format!("未知 provider: {other}"),
                detail: None,
            });
        }
    };
    let body_json = serde_json::to_string(&body).map_err(|error| LlmCallError::Permanent {
        reason: format!("serialize LLM request: {error}"),
        detail: None,
    })?;
    Ok(PreparedLlmRequest {
        provider: config.provider.clone(),
        model: config.model.clone(),
        url,
        headers_for_log,
        body_json,
        message_count: messages.len(),
        tool_count: tools.len(),
    })
}

// BEGIN TEMP_AI_TRANSPORT_DIAGNOSTICS: remove this block and its marked call sites before production release.
// Retained for future transport diagnosis; normal builds must not write request/response logs.
const TEMP_AI_TRANSPORT_DIAGNOSTICS_ENABLED: bool = false;

fn response_headers_for_diagnostics(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers.iter().map(|(name, value)| {
        let name = name.as_str().to_string();
        let value = if name.eq_ignore_ascii_case("set-cookie") {
            "<redacted>".to_string()
        } else {
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        };
        (name, value)
    }).collect()
}

fn diagnostic_log_component(value: &str) -> String {
    let sanitized: String = value.chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-' || *character == '_')
        .take(64)
        .collect();
    if sanitized.is_empty() { "unknown".to_string() } else { sanitized }
}

fn write_transport_failure_log(
    session_id: &str,
    attempt: u32,
    request: &PreparedLlmRequest,
    error: &LlmCallError,
    will_retry: bool,
    retry_delay_ms: Option<u64>,
) -> Result<Option<std::path::PathBuf>, String> {
    use sha2::Digest as _;
    use std::fmt::Write as _;

    if !TEMP_AI_TRANSPORT_DIAGNOSTICS_ENABLED {
        return Ok(None);
    }
    let detail = match error.detail() {
        Some(detail) => detail,
        None => return Ok(None),
    };
    let executable = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let directory = executable.parent().ok_or_else(|| "executable has no parent directory".to_string())?;
    let timestamp = unix_time_ms();
    let filename = format!(
        "GuardMeta-AI-transport-failure-{}-{}-p{}-a{}.log",
        diagnostic_log_component(session_id),
        timestamp,
        std::process::id(),
        attempt,
    );
    let path = directory.join(filename);
    let body_sha256 = hex::encode(sha2::Sha256::digest(request.body_json.as_bytes()));
    let mut output = String::new();
    let _ = writeln!(output, "TEMP_AI_TRANSPORT_DIAGNOSTICS=1");
    let _ = writeln!(output, "remove_before_production_release=true");
    let _ = writeln!(output, "authentication_values_redacted=true");
    let _ = writeln!(output, "timestamp_unix_ms={timestamp}");
    let _ = writeln!(output, "process_id={}", std::process::id());
    let _ = writeln!(output, "executable={}", executable.display());
    let _ = writeln!(output, "session_id={session_id}");
    let _ = writeln!(output, "attempt={attempt}");
    let _ = writeln!(output, "will_retry={will_retry}");
    let _ = writeln!(output, "retry_delay_ms={}", retry_delay_ms.map(|value| value.to_string()).unwrap_or_else(|| "none".to_string()));
    let _ = writeln!(output, "provider={}", request.provider);
    let _ = writeln!(output, "model={}", request.model);
    let _ = writeln!(output, "method=POST");
    let _ = writeln!(output, "url={}", request.url);
    let _ = writeln!(output, "message_count={}", request.message_count);
    let _ = writeln!(output, "tool_count={}", request.tool_count);
    let _ = writeln!(output, "request_body_bytes={}", request.body_json.len());
    let _ = writeln!(output, "request_body_sha256={body_sha256}");
    let _ = writeln!(output, "failure_reason={}", error.reason());
    let _ = writeln!(output, "failure_phase={}", detail.phase);
    let _ = writeln!(output, "started_unix_ms={}", detail.started_unix_ms);
    let _ = writeln!(output, "elapsed_to_headers_ms={}", detail.elapsed_to_headers_ms.map(|value| value.to_string()).unwrap_or_else(|| "none".to_string()));
    let _ = writeln!(output, "elapsed_total_ms={}", detail.elapsed_total_ms);
    let _ = writeln!(output, "response_status={}", detail.response_status.map(|value| value.to_string()).unwrap_or_else(|| "none".to_string()));
    let _ = writeln!(output, "\n=== REQUEST HEADERS (authentication redacted) ===");
    for (name, value) in &request.headers_for_log {
        let _ = writeln!(output, "{name}: {value}");
    }
    let _ = writeln!(output, "content-length: {}", request.body_json.len());
    let _ = writeln!(output, "\n=== REQUEST BODY (exact transmitted JSON) ===");
    let _ = writeln!(output, "{}", request.body_json);
    let _ = writeln!(output, "\n=== RESPONSE HEADERS ===");
    if detail.response_headers.is_empty() {
        let _ = writeln!(output, "<none>");
    } else {
        for (name, value) in &detail.response_headers {
            let _ = writeln!(output, "{name}: {value}");
        }
    }
    let _ = writeln!(output, "\n=== RESPONSE BODY ===");
    let _ = writeln!(output, "{}", detail.response_body.as_deref().unwrap_or("<unavailable>"));
    let _ = writeln!(output, "\n=== TRANSPORT ERROR ===");
    let _ = writeln!(output, "{}", detail.transport_error.as_deref().unwrap_or("<none>"));
    std::fs::write(&path, output.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(Some(path))
}
// END TEMP_AI_TRANSPORT_DIAGNOSTICS

const RETRY_MAX_ATTEMPTS: u32 = 5;
const RETRY_BASE_MS: u64 = 1000;
const RETRY_CAP_MS: u64 = 30_000;

fn backoff_ms(attempt: u32, retry_after_secs: Option<u64>) -> u64 {
    if let Some(sec) = retry_after_secs {
        return (sec.saturating_mul(1000)).min(60_000); // retry-after 上限 60s
    }
    let factor = 1u64 << (attempt.min(10) - 1).max(0);
    (RETRY_BASE_MS.saturating_mul(factor)).min(RETRY_CAP_MS)
}

async fn call_with_retry<F>(
    client: &reqwest::Client,
    config: &super::llm::LlmConfig,
    messages: &[Value],
    tools: &[AiTool],
    max_output_tokens: Option<u32>,
    emit: &F,
    session: &Arc<AiSession>,
) -> Result<(Value, LlmUsage, Vec<ToolCallParsed>), LlmCallError>
where
    F: Fn(&str, Value),
{
    let prepared_request = prepare_llm_request(config, messages, tools, max_output_tokens)?;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if session.is_cancelled() {
            return Err(LlmCallError::Permanent { reason: "用户取消".into(), detail: None });
        }
        // 用 select! 让 HTTP 调用与取消监听并行
        // — 取消触发时立即 drop HTTP future (reqwest 会 abort).
        let call_fut = async {
            match config.provider.as_str() {
                "openai" => call_openai(client, config, &prepared_request).await,
                "anthropic" => call_anthropic(client, config, &prepared_request).await,
                other => Err(LlmCallError::Permanent { reason: format!("未知 provider: {other}"), detail: None }),
            }
        };
        let cancel_fut = async {
            // 200ms 轮询 cancel flag — 用户点取消最多 200ms 反应
            loop {
                if session.is_cancelled() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        };
        let res = tokio::select! {
            biased;
            _ = cancel_fut => {
                return Err(LlmCallError::Permanent { reason: "用户取消".into(), detail: None });
            }
            r = call_fut => r,
        };
        let error = match res {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let retryable = error.is_retryable();
        let will_retry = retryable && attempt < RETRY_MAX_ATTEMPTS;
        let retry_delay_ms = will_retry.then(|| backoff_ms(attempt, error.retry_after_secs()));
        let reason = error.reason().to_string();
        let status = error.status();

        // TEMP_AI_TRANSPORT_DIAGNOSTICS: one complete file per failed provider attempt.
        let (diagnostic_log, diagnostic_log_error) = match write_transport_failure_log(
            &session.id,
            attempt,
            &prepared_request,
            &error,
            will_retry,
            retry_delay_ms,
        ) {
            Ok(path) => (path.map(|value| value.display().to_string()), None),
            Err(log_error) => (None, Some(log_error)),
        };
        emit("llm_transport_diagnostic", json!({
            "attempt": attempt,
            "will_retry": will_retry,
            "status": status,
            "path": diagnostic_log,
            "log_error": diagnostic_log_error,
        }));

        if !retryable {
            return Err(error);
        }
        if !will_retry {
            emit("llm_retry_giveup", json!({
                "attempts": attempt,
                "reason": reason,
                "status": status,
                "diagnostic_log": diagnostic_log,
                "diagnostic_log_error": diagnostic_log_error,
            }));
            return Err(error);
        }
        let delay = retry_delay_ms.unwrap_or(RETRY_BASE_MS);
        emit("llm_retry", json!({
            "attempt": attempt,
            "max": RETRY_MAX_ATTEMPTS,
            "delay_ms": delay,
            "status": status,
            "reason": short_reason(&reason),
            "diagnostic_log": diagnostic_log,
            "diagnostic_log_error": diagnostic_log_error,
        }));
        // 等 delay, 但每 200ms 检一次 cancel 让取消能及时打断
        let mut waited = 0u64;
        while waited < delay {
            if session.is_cancelled() {
                return Err(LlmCallError::Permanent { reason: "用户取消".into(), detail: None });
            }
            let step = (delay - waited).min(200);
            tokio::time::sleep(std::time::Duration::from_millis(step)).await;
            waited += step;
        }
    }
}

fn short_reason(s: &str) -> String {
    // 抽 message 字段 / 截断
    if let Some(start) = s.find("\"message\":\"") {
        let rest = &s[start + 11..];
        if let Some(end) = rest.find('"') {
            return rest[..end].chars().take(120).collect();
        }
    }
    s.chars().take(160).collect()
}

async fn call_openai(
    client: &reqwest::Client,
    config: &super::llm::LlmConfig,
    request: &PreparedLlmRequest,
) -> Result<(Value, LlmUsage, Vec<ToolCallParsed>), LlmCallError> {
    let started_unix_ms = unix_time_ms();
    let started = std::time::Instant::now();
    let r = match client.post(&request.url)
        .bearer_auth(&config.api_key)
        .header("content-type", "application/json")
        .body(request.body_json.clone())
        .send().await
    {
        Ok(response) => response,
        Err(error) => return Err(classify_send_err(error, started_unix_ms, started.elapsed().as_millis())),
    };
    let elapsed_to_headers_ms = started.elapsed().as_millis();
    let status = r.status();
    let response_headers = response_headers_for_diagnostics(r.headers());
    let retry_after = r.headers().get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let text = match r.text().await {
        Ok(text) => text,
        Err(error) => {
            return Err(LlmCallError::Retryable {
                reason: format!("read body: {error}"),
                status: Some(status.as_u16()),
                retry_after_secs: None,
                detail: Some(Box::new(LlmFailureDetail {
                    phase: "read_response_body",
                    started_unix_ms,
                    elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
                    elapsed_total_ms: started.elapsed().as_millis(),
                    response_status: Some(status.as_u16()),
                    response_headers,
                    response_body: None,
                    transport_error: Some(format!("{error:#?}")),
                })),
            });
        }
    };
    let elapsed_total_ms = started.elapsed().as_millis();
    if !status.is_success() {
        return Err(classify_http_err(status, &text, retry_after, LlmFailureDetail {
            phase: "http_status",
            started_unix_ms,
            elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
            elapsed_total_ms,
            response_status: Some(status.as_u16()),
            response_headers,
            response_body: Some(text.clone()),
            transport_error: None,
        }));
    }
    let j: Value = serde_json::from_str(&text)
        .map_err(|error| LlmCallError::Permanent {
            reason: format!("OpenAI 响应非 JSON: {error}: {}", text.chars().take(200).collect::<String>()),
            detail: Some(Box::new(LlmFailureDetail {
                phase: "parse_response_json",
                started_unix_ms,
                elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
                elapsed_total_ms,
                response_status: Some(status.as_u16()),
                response_headers: response_headers.clone(),
                response_body: Some(text.clone()),
                transport_error: Some(format!("{error:#?}")),
            })),
        })?;
    if j.get("error").is_some() || j.get("type").and_then(Value::as_str) == Some("error") {
        let reason = format!("OpenAI provider error: {}", text.chars().take(500).collect::<String>());
        let detail = LlmFailureDetail {
            phase: "provider_error_json",
            started_unix_ms,
            elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
            elapsed_total_ms,
            response_status: Some(status.as_u16()),
            response_headers: response_headers.clone(),
            response_body: Some(text.clone()),
            transport_error: None,
        };
        return Err(if is_context_overflow_body(status, &text) {
            LlmCallError::ContextOverflow { reason, detail: Some(Box::new(detail)) }
        } else {
            LlmCallError::Permanent { reason, detail: Some(Box::new(detail)) }
        });
    }

    let msg = j.pointer("/choices/0/message").cloned().unwrap_or(json!({}));
    let cached_input = j.pointer("/usage/prompt_tokens_details/cached_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let prompt_tokens = j.pointer("/usage/prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let usage = LlmUsage {
        input: prompt_tokens.saturating_sub(cached_input),
        output: j.pointer("/usage/completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        cache_read: cached_input,
        cache_write: 0,
        total: j.pointer("/usage/total_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
    };

    let mut calls = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in arr {
            let id = tc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = tc.pointer("/function/name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let raw_args = tc.pointer("/function/arguments").and_then(|v| v.as_str()).unwrap_or("{}");
            let input: Value = serde_json::from_str(raw_args).unwrap_or(json!({}));
            calls.push(ToolCallParsed { id, name, input });
        }
    }

    Ok((msg, usage, calls))
}

// ===== Anthropic =====

async fn call_anthropic(
    client: &reqwest::Client,
    config: &super::llm::LlmConfig,
    request: &PreparedLlmRequest,
) -> Result<(Value, LlmUsage, Vec<ToolCallParsed>), LlmCallError> {
    let started_unix_ms = unix_time_ms();
    let started = std::time::Instant::now();
    let r = match client.post(&request.url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(request.body_json.clone())
        .send().await
    {
        Ok(response) => response,
        Err(error) => return Err(classify_send_err(error, started_unix_ms, started.elapsed().as_millis())),
    };
    let elapsed_to_headers_ms = started.elapsed().as_millis();
    let status = r.status();
    let response_headers = response_headers_for_diagnostics(r.headers());
    let retry_after = r.headers().get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let text = match r.text().await {
        Ok(text) => text,
        Err(error) => {
            return Err(LlmCallError::Retryable {
                reason: format!("read body: {error}"),
                status: Some(status.as_u16()),
                retry_after_secs: None,
                detail: Some(Box::new(LlmFailureDetail {
                    phase: "read_response_body",
                    started_unix_ms,
                    elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
                    elapsed_total_ms: started.elapsed().as_millis(),
                    response_status: Some(status.as_u16()),
                    response_headers,
                    response_body: None,
                    transport_error: Some(format!("{error:#?}")),
                })),
            });
        }
    };
    let elapsed_total_ms = started.elapsed().as_millis();
    if !status.is_success() {
        return Err(classify_http_err(status, &text, retry_after, LlmFailureDetail {
            phase: "http_status",
            started_unix_ms,
            elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
            elapsed_total_ms,
            response_status: Some(status.as_u16()),
            response_headers,
            response_body: Some(text.clone()),
            transport_error: None,
        }));
    }
    let j: Value = serde_json::from_str(&text)
        .map_err(|error| LlmCallError::Permanent {
            reason: format!("Anthropic 响应非 JSON: {error}: {}", text.chars().take(200).collect::<String>()),
            detail: Some(Box::new(LlmFailureDetail {
                phase: "parse_response_json",
                started_unix_ms,
                elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
                elapsed_total_ms,
                response_status: Some(status.as_u16()),
                response_headers: response_headers.clone(),
                response_body: Some(text.clone()),
                transport_error: Some(format!("{error:#?}")),
            })),
        })?;
    if j.get("error").is_some() || j.get("type").and_then(Value::as_str) == Some("error") {
        let reason = format!("Anthropic provider error: {}", text.chars().take(500).collect::<String>());
        let detail = LlmFailureDetail {
            phase: "provider_error_json",
            started_unix_ms,
            elapsed_to_headers_ms: Some(elapsed_to_headers_ms),
            elapsed_total_ms,
            response_status: Some(status.as_u16()),
            response_headers: response_headers.clone(),
            response_body: Some(text.clone()),
            transport_error: None,
        };
        return Err(if is_context_overflow_body(status, &text) {
            LlmCallError::ContextOverflow { reason, detail: Some(Box::new(detail)) }
        } else {
            LlmCallError::Permanent { reason, detail: Some(Box::new(detail)) }
        });
    }

    let usage = LlmUsage {
        input: j.pointer("/usage/input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        output: j.pointer("/usage/output_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        cache_read: j.pointer("/usage/cache_read_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        cache_write: j.pointer("/usage/cache_creation_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        total: 0,
    };

    let mut text_parts = Vec::new();
    let mut assistant_calls = Vec::new();
    let mut calls = Vec::new();
    if let Some(arr) = j.get("content").and_then(|v| v.as_array()) {
        for blk in arr {
            match blk.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(text) = blk.get("text").and_then(Value::as_str) {
                        text_parts.push(text.to_string());
                    }
                }
                Some("tool_use") => {
                    let id = blk.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                    let name = blk.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                    let input = blk.get("input").cloned().unwrap_or(json!({}));
                    if let Some(call) = canonical_tool_call(&id, &name, &input) {
                        assistant_calls.push(call);
                    }
                    calls.push(ToolCallParsed { id, name, input });
                }
                _ => {}
            }
        }
    }

    let text = text_parts.join("\n");
    let mut assistant = json!({
        "role": "assistant",
        "content": if text.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !assistant_calls.is_empty() {
        assistant["tool_calls"] = Value::Array(assistant_calls);
    }

    Ok((assistant, usage, calls))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_call(id: &str, name: &str) -> Value {
        json!({
            "id": id,
            "type": "function",
            "function": { "name": name, "arguments": "{}" },
        })
    }

    #[test]
    fn debugger_control_tools_hide_transport_mode_and_accept_step_counts() {
        let tools = tool_table();
        for name in [
            "restart_debuggee",
            "resume_execution",
            "step_into",
            "step_over",
            "step_out",
            "get_registers",
            "set_registers",
            "set_breakpoint",
            "clear_breakpoint",
            "list_breakpoints",
        ] {
            let tool = tools.iter().find(|tool| tool.name == name).expect(name);
            assert!(tool.input_schema.pointer("/properties/mode").is_none());
        }
        assert_eq!(step_count(&json!({})), Ok(1));
        assert_eq!(step_count(&json!({ "count": 7 })), Ok(7));
        assert!(step_count(&json!({ "count": 0 })).is_err());
        assert!(step_count(&json!({ "count": 1001 })).is_err());
    }

    #[test]
    fn register_patch_changes_only_requested_hex_registers() {
        let mut context = crate::commands::debugger_ui::ThreadContextView {
            tid: 7,
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rbp: 7,
            rsp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            rip: 17,
            rflags: 0x202,
            cs: 0x33,
            ss: 0x2b,
        };
        let changed = apply_register_patch(
            &mut context,
            Some(&json!({ "rax": "0x1234", "RIP": "0x5678", "rflags": "0x246" })),
        ).expect("register patch");
        assert_eq!(changed, vec!["rax", "rflags", "rip"]);
        assert_eq!(context.rax, 0x1234);
        assert_eq!(context.rip, 0x5678);
        assert_eq!(context.rflags, 0x246);
        assert_eq!(context.rbx, 2);
    }

    #[test]
    fn drops_orphaned_tool_results_without_cutting_valid_transactions() {
        let messages = vec![
            json!({ "role": "tool", "tool_call_id": "orphan", "content": "old" }),
            json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [canonical_call("call-1", "read_memory")],
            }),
            json!({ "role": "tool", "tool_call_id": "call-1", "content": "ok" }),
        ];
        let normalized = normalize_provider_history(&messages);
        assert_eq!(normalized.len(), 2);
        assert_eq!(normalized[0].pointer("/tool_calls/0/id").and_then(Value::as_str), Some("call-1"));
        assert_eq!(normalized[1].get("tool_call_id").and_then(Value::as_str), Some("call-1"));
    }

    #[test]
    fn converts_anthropic_history_to_canonical_and_back_at_provider_boundary() {
        let messages = vec![
            json!({
                "role": "assistant",
                "content": [
                    { "type": "thinking", "thinking": "private" },
                    { "type": "text", "text": "checking" },
                    { "type": "tool_use", "id": "tool-1", "name": "list_modules", "input": { "pid": 7 } }
                ]
            }),
            json!({
                "role": "user",
                "content": [
                    { "type": "tool_result", "tool_use_id": "tool-1", "content": "done" }
                ]
            }),
        ];
        let canonical = normalize_provider_history(&messages);
        assert_eq!(canonical.len(), 2);
        assert!(canonical[0].get("content").is_some_and(Value::is_string));
        assert_eq!(canonical[0].pointer("/tool_calls/0/id").and_then(Value::as_str), Some("tool-1"));
        assert_eq!(canonical[1].get("role").and_then(Value::as_str), Some("tool"));

        let openai = openai_wire_messages(&canonical);
        assert_eq!(openai[0].pointer("/tool_calls/0/id").and_then(Value::as_str), Some("tool-1"));
        assert_eq!(openai[1].get("tool_call_id").and_then(Value::as_str), Some("tool-1"));

        let (_, anthropic) = anthropic_wire_messages(&canonical);
        assert_eq!(anthropic[0].pointer("/content/1/type").and_then(Value::as_str), Some("tool_use"));
        assert_eq!(anthropic[1].pointer("/content/0/type").and_then(Value::as_str), Some("tool_result"));
    }

    #[test]
    fn compaction_split_keeps_tool_call_and_results_together() {
        let mut messages = vec![json!({
            "role": "system",
            "content": "base",
            "_guardmeta": { "kind": "base_system" },
        })];
        messages.push(json!({ "role": "user", "content": "start" }));
        messages.push(json!({ "role": "assistant", "content": "old turn" }));
        messages.push(json!({ "role": "user", "content": "tool turn" }));
        let expected_split = messages.len() - 1;
        messages.push(json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [
                canonical_call("call-a", "a"),
                canonical_call("call-b", "b"),
            ],
        }));
        messages.push(json!({ "role": "tool", "tool_call_id": "call-a", "content": "a" }));
        messages.push(json!({ "role": "tool", "tool_call_id": "call-b", "content": "b" }));
        messages.push(json!({ "role": "user", "content": "latest turn" }));
        messages.push(json!({ "role": "assistant", "content": "latest answer" }));
        let split = compaction_split(&messages, 1_000_000, Some(800_000), true, 8_000).expect("compaction split");
        assert_eq!(split, expected_split);
        assert_eq!(messages[split].get("role").and_then(Value::as_str), Some("user"));
        assert_eq!(messages[split + 1].get("role").and_then(Value::as_str), Some("assistant"));
        assert_eq!(messages[split + 2].get("role").and_then(Value::as_str), Some("tool"));
    }

    #[test]
    fn tool_preview_keeps_opencode_sized_output_bounded() {
        let text = (0..3_000).map(|index| format!("line-{index}"))
            .collect::<Vec<_>>().join("\n");
        let preview = bounded_tool_preview(&text, "... marker ...");
        assert!(preview.len() <= TOOL_OUTPUT_MAX_BYTES);
        assert!(preview.contains("... marker ..."));
        assert!(preview.starts_with("line-0"));
        assert!(preview.contains("line-2999"));
    }

    #[test]
    fn compaction_budget_preserves_requested_safety_window() {
        let config = super::super::llm::LlmConfig {
            provider: "openai".to_string(),
            base_url: "https://example.invalid/v1".to_string(),
            api_key: "test".to_string(),
            model: "gpt-4.1".to_string(),
            temperature: None,
            reasoning_effort: None,
            context_tokens: None,
            input_tokens: None,
            output_tokens: None,
            output_token_max: None,
            compaction_reserved_tokens: None,
        };
        assert_eq!(max_output_tokens(&config), Some(32_000));
        assert_eq!(usable_input_tokens(&config), Some(968_000));
        assert_eq!(estimate_json_tokens(&"a".repeat(400)), 100);
        assert_eq!(estimate_json_tokens("测试上下文"), 5);
    }

    #[test]
    fn one_million_context_catalog_aliases_use_opus_profile() {
        for model in ["gpt-5.5", "gpt-5.6", "claude-opus-4.7", "claude-fable-5"] {
            let config = super::super::llm::LlmConfig {
                provider: "openai".to_string(),
                base_url: "https://example.invalid/v1".to_string(),
                api_key: "test".to_string(),
                model: model.to_string(),
                temperature: None,
                reasoning_effort: None,
                context_tokens: None,
                input_tokens: None,
                output_tokens: None,
                output_token_max: None,
                compaction_reserved_tokens: None,
            };
            assert_eq!(model_limits(&config).context, Some(1_000_000));
            assert_eq!(model_limits(&config).input, None);
            assert_eq!(model_limits(&config).output, Some(128_000));
        }
    }

    #[test]
    fn compaction_request_uses_separate_output_budget() {
        let config = super::super::llm::LlmConfig {
            provider: "openai".to_string(),
            base_url: "https://example.invalid/v1".to_string(),
            api_key: "test".to_string(),
            model: "gpt-5.5".to_string(),
            temperature: Some(0.2),
            reasoning_effort: None,
            context_tokens: None,
            input_tokens: None,
            output_tokens: None,
            output_token_max: None,
            compaction_reserved_tokens: None,
        };
        let request = prepare_llm_request(
            &config,
            &[json!({ "role": "user", "content": "compact" })],
            &[],
            max_output_tokens(&config),
        ).expect("prepare compaction request");
        let body: Value = serde_json::from_str(&request.body_json).expect("request JSON");
        assert_eq!(body.get("max_tokens").and_then(Value::as_u64), Some(32_000));
    }

    #[test]
    fn provider_requests_apply_model_reasoning_variants() {
        let openai = super::super::llm::LlmConfig {
            provider: "openai".to_string(),
            base_url: "https://example.invalid/v1".to_string(),
            api_key: "test".to_string(),
            model: "gpt-5.6-sol".to_string(),
            temperature: Some(0.2),
            reasoning_effort: Some("max".to_string()),
            context_tokens: None,
            input_tokens: None,
            output_tokens: None,
            output_token_max: None,
            compaction_reserved_tokens: None,
        };
        let openai_request = prepare_llm_request(
            &openai,
            &[json!({ "role": "user", "content": "reason" })],
            &[],
            max_output_tokens(&openai),
        ).expect("OpenAI reasoning request");
        let openai_body: Value = serde_json::from_str(&openai_request.body_json).expect("OpenAI JSON");
        assert_eq!(openai_body.get("reasoning_effort").and_then(Value::as_str), Some("max"));
        assert!(openai_body.get("temperature").is_none());

        let anthropic = super::super::llm::LlmConfig {
            provider: "anthropic".to_string(),
            model: "claude-fable-5".to_string(),
            reasoning_effort: Some("xhigh".to_string()),
            ..openai
        };
        let anthropic_request = prepare_llm_request(
            &anthropic,
            &[json!({ "role": "user", "content": "reason" })],
            &[],
            max_output_tokens(&anthropic),
        ).expect("Anthropic reasoning request");
        let anthropic_body: Value = serde_json::from_str(&anthropic_request.body_json).expect("Anthropic JSON");
        assert_eq!(anthropic_body.pointer("/thinking/type").and_then(Value::as_str), Some("adaptive"));
        assert_eq!(anthropic_body.pointer("/output_config/effort").and_then(Value::as_str), Some("xhigh"));
        assert!(anthropic_body.get("temperature").is_none());
    }

    #[test]
    fn opencode_overflow_and_usage_rules_are_preserved() {
        assert!(is_context_overflow_body(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":{"code":"context_length_exceeded"}}"#,
        ));
        assert!(is_context_overflow_body(
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            "gateway rejected request",
        ));
        assert!(!is_context_overflow_body(
            reqwest::StatusCode::BAD_GATEWAY,
            "upstream unavailable",
        ));

        let usage = LlmUsage {
            input: 700,
            output: 100,
            cache_read: 150,
            cache_write: 50,
            total: 0,
        };
        assert_eq!(usage.context_tokens(), 1_000);
        assert_eq!(LlmUsage { total: 900, ..usage }.context_tokens(), 900);

        let config = super::super::llm::LlmConfig {
            provider: "openai".to_string(),
            base_url: "https://example.invalid/v1".to_string(),
            api_key: "test".to_string(),
            model: "gpt-5.6-sol".to_string(),
            temperature: None,
            reasoning_effort: None,
            context_tokens: None,
            input_tokens: None,
            output_tokens: None,
            output_token_max: None,
            compaction_reserved_tokens: None,
        };
        assert_eq!(usable_input_tokens(&config), Some(968_000));
        assert_eq!(max_output_tokens(&config), Some(32_000));
        let mut capped = config.clone();
        capped.output_token_max = Some(200_000);
        assert_eq!(max_output_tokens(&capped), Some(128_000));
        capped.output_token_max = Some(16_000);
        assert_eq!(max_output_tokens(&capped), Some(16_000));
    }
}
