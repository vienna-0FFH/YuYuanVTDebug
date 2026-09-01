//! LLM 调用 — 后端 reqwest 实现(避开 webview CORS / fetch 限制) (P82)
//!
//! 双协议:
//!   - OpenAI: POST {base}/chat/completions (Bearer)
//!   - Anthropic: POST {base}/messages (x-api-key + anthropic-version)
//!
//! 用户传 base URL + key + model + messages,后端发 HTTPS/HTTP 请求拿响应。

use serde::{Deserialize, Serialize};

use crate::util::error::{AppError, AppResult};

const OPENCODE_OUTPUT_TOKEN_MAX: u32 = 32_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LlmConfig {
    pub provider: String,       // "openai" | "anthropic"
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub temperature: Option<f32>,
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    /// Optional OpenCode-style model limits. Omitted values are resolved from
    /// the provider/model catalog or treated as unknown.
    #[serde(default)]
    pub context_tokens: Option<u64>,
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub output_tokens: Option<u64>,
    /// Per-request output cap. This is an override, not the model limit.
    #[serde(default)]
    pub output_token_max: Option<u32>,
    /// Reserved input budget for compaction and the next response.
    #[serde(default)]
    pub compaction_reserved_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LlmMessage {
    pub role: String,           // "system" | "user" | "assistant"
    pub content: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct LlmCallOpts {
    pub json_object: Option<bool>,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LlmResponse {
    pub text: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LlmCallReq {
    pub config: LlmConfig,
    pub messages: Vec<LlmMessage>,
    #[serde(default)]
    pub opts: LlmCallOpts,
}

fn trim_url(s: &str) -> String {
    let mut t = s.trim().trim_end_matches('/').to_string();
    if !t.starts_with("http://") && !t.starts_with("https://") {
        t = format!("https://{}", t);
    }
    t
}

#[tauri::command]
pub async fn dbg_llm_call(req: LlmCallReq) -> AppResult<LlmResponse> {
    let max_tokens = req.opts.max_tokens
        .or(req.config.output_token_max)
        .or(Some(OPENCODE_OUTPUT_TOKEN_MAX));
    let temperature = req.config.temperature.unwrap_or(0.2);
    let base = trim_url(&req.config.base_url);
    let json_object = req.opts.json_object.unwrap_or(false);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| AppError::Internal(format!("reqwest build: {e}")))?;

    match req.config.provider.as_str() {
        "openai" => {
            let url = format!("{}/chat/completions", base);
            let msgs: Vec<serde_json::Value> = req.messages.iter().map(|m| {
                serde_json::json!({ "role": m.role, "content": m.content })
            }).collect();
            let mut body = serde_json::json!({
                "model": req.config.model,
                "messages": msgs,
                "temperature": temperature,
            });
            if let Some(effort) = req.config.reasoning_effort.as_deref() {
                body["reasoning_effort"] = serde_json::json!(effort);
                if let Some(object) = body.as_object_mut() {
                    object.remove("temperature");
                }
            }
            if let Some(max_tokens) = max_tokens {
                body["max_tokens"] = serde_json::json!(max_tokens);
            }
            if json_object {
                body["response_format"] = serde_json::json!({ "type": "json_object" });
            }
            let r = client
                .post(&url)
                .bearer_auth(&req.config.api_key)
                .json(&body)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("HTTP: {e}")))?;
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(AppError::Internal(format!("OpenAI {}: {}", status, text)));
            }
            let j: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| AppError::Internal(format!("响应非 JSON: {e}: {}", text.chars().take(200).collect::<String>())))?;
            let content = j.pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(LlmResponse {
                text: content,
                input_tokens: j.pointer("/usage/prompt_tokens").and_then(|v| v.as_u64()),
                output_tokens: j.pointer("/usage/completion_tokens").and_then(|v| v.as_u64()),
                cache_read_tokens: j.pointer("/usage/prompt_tokens_details/cached_tokens").and_then(|v| v.as_u64()),
                cache_write_tokens: None,
                total_tokens: j.pointer("/usage/total_tokens").and_then(|v| v.as_u64()),
            })
        }
        "anthropic" => {
            let url = format!("{}/messages", base);
            // 抽 system,其余按 user/assistant
            let sys: String = req.messages.iter()
                .filter(|m| m.role == "system")
                .map(|m| m.content.clone())
                .collect::<Vec<_>>()
                .join("\n\n");
            let turns: Vec<serde_json::Value> = req.messages.iter()
                .filter(|m| m.role != "system")
                .map(|m| serde_json::json!({ "role": m.role, "content": m.content }))
                .collect();
            let mut body = serde_json::json!({
                "model": req.config.model,
                "temperature": temperature,
                "messages": turns,
            });
            body["max_tokens"] = serde_json::json!(max_tokens.unwrap_or(4096));
            if !sys.is_empty() {
                body["system"] = serde_json::Value::String(sys);
            }
            if let Some(effort) = req.config.reasoning_effort.as_deref() {
                body["thinking"] = serde_json::json!({ "type": "adaptive", "display": "summarized" });
                body["output_config"] = serde_json::json!({ "effort": effort });
                if let Some(object) = body.as_object_mut() {
                    object.remove("temperature");
                }
            }
            let r = client
                .post(&url)
                .header("x-api-key", &req.config.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("HTTP: {e}")))?;
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                return Err(AppError::Internal(format!("Anthropic {}: {}", status, text)));
            }
            let j: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| AppError::Internal(format!("响应非 JSON: {e}: {}", text.chars().take(200).collect::<String>())))?;
            // content 是数组,取所有 type=text 的块拼接
            let content_arr = j.get("content").and_then(|v| v.as_array());
            let content = match content_arr {
                Some(arr) => arr.iter()
                    .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join(""),
                None => String::new(),
            };
            Ok(LlmResponse {
                text: content,
                input_tokens: j.pointer("/usage/input_tokens").and_then(|v| v.as_u64()),
                output_tokens: j.pointer("/usage/output_tokens").and_then(|v| v.as_u64()),
                cache_read_tokens: j.pointer("/usage/cache_read_input_tokens").and_then(|v| v.as_u64()),
                cache_write_tokens: j.pointer("/usage/cache_creation_input_tokens").and_then(|v| v.as_u64()),
                total_tokens: None,
            })
        }
        other => Err(AppError::Internal(format!("未知 provider: {}", other))),
    }
}
