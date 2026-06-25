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
            description: "从目标进程读字节. size <=4096. \
                          size > 512 时只返首 128 + 尾 64 字节 + artifact_id, 全文用 read_artifact(id) 取.".into(),
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
    /// 对话历史 (oai 协议格式) — 前端维护
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
    use tauri::Manager;
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
                    other => json!({ "ok": true, "kind": a.kind, "data": other }),
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
            match crate::commands::debugger_ui::dbg_read_memory(state, pid, addr, size).await {
                Ok(v) => {
                    let hex: String = v.bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    if v.bytes.len() > 512 {
                        // 大块: 只回首尾 + artifact
                        let head_hex: String = v.bytes.iter().take(128).map(|b| format!("{:02x}", b)).collect();
                        let n = v.bytes.len();
                        let tail_start = if n > 64 { n - 64 } else { 0 };
                        let tail_hex: String = v.bytes[tail_start..].iter().map(|b| format!("{:02x}", b)).collect();
                        let aid = session.store_artifact(store, "memory",
                            format!("read_memory 0x{:x}+{}", addr, v.bytes.len()),
                            v.bytes.len() as u64, json!({ "hex": hex }));
                        json!({
                            "ok": true,
                            "address": format!("0x{:x}", addr),
                            "size": v.bytes.len(),
                            "head_128_hex": head_hex,
                            "tail_64_hex": tail_hex,
                            "artifact_id": aid,
                        })
                    } else {
                        json!({
                            "ok": true,
                            "address": format!("0x{:x}", addr),
                            "size": v.bytes.len(),
                            "hex": hex,
                            "truncated": v.truncated,
                        })
                    }
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
            match crate::commands::debugger_ui::dbg_read_memory(state.clone(), pid, addr, size).await {
                Ok(rd) => match crate::commands::debugger_ui::dbg_disasm(addr, rd.bytes).await {
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
     工作循环(可达 50 轮, 直到调 mark_complete):\n\
     1. 摸清目标: list_processes / list_modules\n\
     2. 静态逆向: list_functions / list_strings / list_imports / list_exports\n\
        xref_to(谁引用此地址) / xref_from(此指令引用什么) / get_function(此地址属于哪个函数)\n\
     3. 定位: find_globals / aob_scan / scan_first → scan_next 收敛\n\
     4. 读取: read_memory / disasm / resolve_symbol / call_stack\n\
        find_who_accesses(pid, address, mode='write'|'rw'): 装 HWBP 找出谁改/谁访问了内存 \
        (CE Find out what accesses this address 等价). 找血量 damage 函数 / 找指针都靠这个.\n\
     5. 注解: set_label / set_comment / define_function (持久化到项目, disasm 自动附加)\n\
     6. 脚本: lua_eval 跑自定义逻辑\n\
     7. 文件: read_file / write_file / append_file / list_dir / make_dir / \
        file_exists / delete_file (默认相对 workspace, AI 调用默认允许绝对路径)\n\
     8. 联网: web_search 查文档/资料, web_fetch 拉具体 URL 看正文\n\
     9. 完成时调 mark_complete(summary='...') 立即终止\n\
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

// 旧 dbg_ai_chat 在 P87.1 之后由 dbg_ai_run 取代 (流式 + 取消 + artifact + 50 轮 + 并行).
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

use crate::commands::ai_session::{AiSession, AiSessionStore, append_log, list_sessions, load_session, delete_session, SessionFileInfo};

#[derive(Debug, Deserialize)]
pub struct AiRunReq {
    pub session_id: String,
    pub config: super::llm::LlmConfig,
    /// 完整 history (前端维护)
    pub messages: Vec<Value>,
    pub enabled_tools: Option<Vec<String>>,
    pub max_rounds: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AiRunResp {
    pub rounds: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
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

    let max_rounds = req.max_rounds.unwrap_or(50).min(80);
    let provider = req.config.provider.clone();
    let mut tools = filter_tools(req.enabled_tools.as_deref());
    // P115: 合并所有 connected MCP server 的工具
    {
        use tauri::Manager;
        let reg = app.state::<Arc<McpRegistry>>();
        append_mcp_tools(reg.inner(), &mut tools).await;
    }
    let tools = tools;

    let mut messages = req.messages.clone();
    if !messages.first().and_then(|m| m.get("role")).and_then(|r| r.as_str()).map(|r| r == "system").unwrap_or(false) {
        messages.insert(0, json!({"role":"system","content": system_prompt()}));
    }

    let event_name = format!("ai-run::{}", req.session_id);
    let emit = |kind: &str, data: Value| {
        let _ = app.emit(&event_name, json!({ "kind": kind, "data": data }));
    };

    // 把 user 输入(最后一条 user 消息)写日志
    if let Some(last_user) = messages.iter().rev().find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user")) {
        let _ = append_log(&req.session_id, &json!({ "kind": "user", "payload": last_user }));
    }

    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut rounds = 0u32;
    let mut truncated = false;
    let mut completed = false;
    let mut final_summary: Option<String> = None;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .map_err(|e| AppError::Internal(format!("reqwest build: {e}")))?;

    loop {
        if session.is_cancelled() {
            emit("complete", json!({ "cancelled": true, "rounds": rounds }));
            break;
        }
        if rounds >= max_rounds { truncated = true; emit("complete", json!({"truncated":true,"rounds":rounds})); break; }

        emit("round_start", json!({ "round": rounds }));

        // 带重试调 LLM. 5xx/429/网络错 → 指数退避. 4xx → 立即放弃.
        let llm_res = call_with_retry(&client, &req.config, &messages, &tools, &emit, &session).await;
        let (assistant_msg, in_tok, out_tok, tool_calls) = match llm_res {
            Ok(t) => t,
            Err(e) => {
                let err_str = match &e {
                    LlmCallError::Retryable { reason, .. } | LlmCallError::Permanent { reason } => reason.clone(),
                };
                emit("error", json!({ "stage": "llm_call", "error": err_str }));
                emit("complete", json!({ "error": err_str, "rounds": rounds }));
                return Err(e.into_app_err());
            }
        };

        total_in += in_tok;
        total_out += out_tok;

        messages.push(assistant_msg.clone());
        let _ = append_log(&req.session_id, &json!({ "kind": "assistant", "payload": assistant_msg }));
        emit("assistant", json!({ "message": assistant_msg, "in": in_tok, "out": out_tok }));

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
        for (id, _name, r) in results {
            match r {
                DispatchResult::Done(s) => {
                    done_summary = Some(s.clone());
                    tool_value_pairs.push((id, json!({ "ok": true, "completed": true, "summary": s })));
                }
                DispatchResult::Value(v) => tool_value_pairs.push((id, v)),
            }
        }

        // 协议组装回灌
        match provider.as_str() {
            "openai" => {
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
            }
            "anthropic" => {
                let blocks: Vec<Value> = tool_value_pairs.into_iter().map(|(id, result)| json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "content": result.to_string(),
                })).collect();
                let m = json!({ "role": "user", "content": blocks });
                messages.push(m.clone());
                let _ = append_log(&req.session_id, &json!({ "kind": "tool_result", "payload": m }));
                emit("tool_message", json!({ "message": m }));
            }
            _ => {}
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
pub fn dbg_ai_session_load(session_id: String) -> AppResult<Vec<Value>> {
    load_session(&session_id).map_err(|e| AppError::Internal(format!("load: {e}")))
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

fn trim_url(s: &str) -> String {
    let mut t = s.trim().trim_end_matches('/').to_string();
    if !t.starts_with("http://") && !t.starts_with("https://") {
        t = format!("https://{}", t);
    }
    t
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
    },
    /// 永久错误 — 4xx 业务错 / 协议解析失败 — 不重试, 直接抛出
    Permanent { reason: String },
}

impl LlmCallError {
    fn into_app_err(self) -> AppError {
        match self {
            LlmCallError::Retryable { reason, .. } | LlmCallError::Permanent { reason } => {
                AppError::Internal(reason)
            }
        }
    }
}

/// 判定 HTTP status 是不是值得重试的
fn classify_http_err(status: reqwest::StatusCode, body: &str, retry_after: Option<u64>) -> LlmCallError {
    let code = status.as_u16();
    let reason = format!("HTTP {}: {}", status, body.chars().take(500).collect::<String>());
    // 重试: 5xx, 429, 408 timeout, 上游网关错
    if code == 408 || code == 425 || code == 429 || (500..=599).contains(&code) {
        LlmCallError::Retryable { reason, status: Some(code), retry_after_secs: retry_after }
    } else {
        // 401/403/400 等 — 不重试
        LlmCallError::Permanent { reason }
    }
}

fn classify_send_err(e: reqwest::Error) -> LlmCallError {
    // 连接错 / 超时 / DNS / TLS 握手等 — 全部 retryable
    LlmCallError::Retryable {
        reason: format!("HTTP send: {e}"),
        status: None,
        retry_after_secs: None,
    }
}

/// 重试上限 + 退避基数 (毫秒). 第 N 次重试等 base * 2^(N-1), 上限 30s.
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
    emit: &F,
    session: &Arc<AiSession>,
) -> Result<(Value, u64, u64, Vec<ToolCallParsed>), LlmCallError>
where
    F: Fn(&str, Value),
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        if session.is_cancelled() {
            return Err(LlmCallError::Permanent { reason: "用户取消".into() });
        }
        // 用 select! 让 HTTP 调用与取消监听并行
        // — 取消触发时立即 drop HTTP future (reqwest 会 abort).
        let call_fut = async {
            match config.provider.as_str() {
                "openai" => call_openai(client, config, messages, tools).await,
                "anthropic" => call_anthropic(client, config, messages, tools).await,
                other => Err(LlmCallError::Permanent { reason: format!("未知 provider: {other}") }),
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
                return Err(LlmCallError::Permanent { reason: "用户取消".into() });
            }
            r = call_fut => r,
        };
        match res {
            Ok(v) => return Ok(v),
            Err(LlmCallError::Permanent { reason }) => {
                return Err(LlmCallError::Permanent { reason });
            }
            Err(LlmCallError::Retryable { reason, status, retry_after_secs }) => {
                if attempt >= RETRY_MAX_ATTEMPTS {
                    emit("llm_retry_giveup", json!({
                        "attempts": attempt,
                        "reason": reason,
                        "status": status,
                    }));
                    return Err(LlmCallError::Retryable { reason, status, retry_after_secs });
                }
                let delay = backoff_ms(attempt, retry_after_secs);
                emit("llm_retry", json!({
                    "attempt": attempt,
                    "max": RETRY_MAX_ATTEMPTS,
                    "delay_ms": delay,
                    "status": status,
                    "reason": short_reason(&reason),
                }));
                // 等 delay, 但每 200ms 检一次 cancel 让取消能及时打断
                let mut waited = 0u64;
                while waited < delay {
                    if session.is_cancelled() {
                        return Err(LlmCallError::Permanent { reason: "用户取消".into() });
                    }
                    let step = (delay - waited).min(200);
                    tokio::time::sleep(std::time::Duration::from_millis(step)).await;
                    waited += step;
                }
            }
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
    messages: &[Value],
    tools: &[AiTool],
) -> Result<(Value, u64, u64, Vec<ToolCallParsed>), LlmCallError> {
    let url = format!("{}/chat/completions", trim_url(&config.base_url));

    let tool_decls: Vec<Value> = tools.iter().map(|t| json!({
        "type": "function",
        "function": {
            "name": t.name,
            "description": t.description,
            "parameters": t.input_schema,
        }
    })).collect();

    let body = json!({
        "model": config.model,
        "messages": messages,
        "tools": tool_decls,
        "temperature": config.temperature.unwrap_or(0.2),
        "max_tokens": 4096,
    });

    let r = client.post(&url)
        .bearer_auth(&config.api_key)
        .json(&body)
        .send().await
        .map_err(classify_send_err)?;
    let status = r.status();
    let retry_after = r.headers().get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let text = r.text().await
        .map_err(|e| LlmCallError::Retryable { reason: format!("read body: {e}"), status: Some(status.as_u16()), retry_after_secs: None })?;
    if !status.is_success() {
        return Err(classify_http_err(status, &text, retry_after));
    }
    let j: Value = serde_json::from_str(&text)
        .map_err(|e| LlmCallError::Permanent { reason: format!("OpenAI 响应非 JSON: {e}: {}", text.chars().take(200).collect::<String>()) })?;

    let msg = j.pointer("/choices/0/message").cloned().unwrap_or(json!({}));
    let in_tok = j.pointer("/usage/prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let out_tok = j.pointer("/usage/completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0);

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

    Ok((msg, in_tok, out_tok, calls))
}

// ===== Anthropic =====

async fn call_anthropic(
    client: &reqwest::Client,
    config: &super::llm::LlmConfig,
    messages: &[Value],
    tools: &[AiTool],
) -> Result<(Value, u64, u64, Vec<ToolCallParsed>), LlmCallError> {
    let url = format!("{}/messages", trim_url(&config.base_url));

    // 分离 system + turns
    let mut sys = String::new();
    let mut turns: Vec<Value> = Vec::new();
    for m in messages {
        let role = m.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if role == "system" {
            if let Some(s) = m.get("content").and_then(|v| v.as_str()) {
                if !sys.is_empty() { sys.push_str("\n\n"); }
                sys.push_str(s);
            }
        } else if role == "tool" {
            // 不会在 anthropic 路径出现, 跳过
            continue;
        } else {
            turns.push(m.clone());
        }
    }

    let tool_decls: Vec<Value> = tools.iter().map(|t| json!({
        "name": t.name,
        "description": t.description,
        "input_schema": t.input_schema,
    })).collect();

    let mut body = json!({
        "model": config.model,
        "messages": turns,
        "tools": tool_decls,
        "max_tokens": 4096,
        "temperature": config.temperature.unwrap_or(0.2),
    });
    if !sys.is_empty() { body["system"] = Value::String(sys); }

    let r = client.post(&url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send().await
        .map_err(classify_send_err)?;
    let status = r.status();
    let retry_after = r.headers().get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let text = r.text().await
        .map_err(|e| LlmCallError::Retryable { reason: format!("read body: {e}"), status: Some(status.as_u16()), retry_after_secs: None })?;
    if !status.is_success() {
        return Err(classify_http_err(status, &text, retry_after));
    }
    let j: Value = serde_json::from_str(&text)
        .map_err(|e| LlmCallError::Permanent { reason: format!("Anthropic 响应非 JSON: {e}: {}", text.chars().take(200).collect::<String>()) })?;

    let in_tok = j.pointer("/usage/input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let out_tok = j.pointer("/usage/output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);

    let content = j.get("content").cloned().unwrap_or(json!([]));
    let assistant = json!({ "role": "assistant", "content": content });

    let mut calls = Vec::new();
    if let Some(arr) = j.get("content").and_then(|v| v.as_array()) {
        for blk in arr {
            if blk.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                let id = blk.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let name = blk.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let input = blk.get("input").cloned().unwrap_or(json!({}));
                calls.push(ToolCallParsed { id, name, input });
            }
        }
    }

    Ok((assistant, in_tok, out_tok, calls))
}
