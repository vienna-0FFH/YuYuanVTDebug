/**
 * LLM 客户端 — 调后端 (P82) Rust 端 reqwest 发请求,
 * 绕过 webview fetch 的 CORS / 第三方代理问题。
 */

import { invoke } from "@tauri-apps/api/core";

export type LlmProvider = "openai" | "anthropic";

export interface LlmConfig {
  provider: LlmProvider;
  base_url: string;
  api_key: string;
  model: string;
  temperature?: number;
}

const STORAGE_KEY = "netr-llm";

export const DEFAULT_BASE_URLS: Record<LlmProvider, string> = {
  openai: "https://api.openai.com/v1",
  anthropic: "https://api.anthropic.com/v1",
};

export function loadLlmConfig(): LlmConfig | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const c = JSON.parse(raw) as LlmConfig;
    if (!c.provider || !c.base_url || !c.api_key || !c.model) return null;
    return c;
  } catch { return null; }
}

export function saveLlmConfig(c: LlmConfig) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(c));
  // 同步落盘 — webview localStorage 偶尔被清, 磁盘文件兜底
  void invoke("ai_config_save", { config: c }).catch(() => {});
}

export function clearLlmConfig() {
  localStorage.removeItem(STORAGE_KEY);
  void invoke("ai_config_clear").catch(() => {});
}

/**
 * 启动时: 如果 localStorage 没有 (清缓存 / 第一次进 / 重装),
 * 从磁盘恢复. 同步路径调不到 invoke, 必须 await.
 */
export async function hydrateLlmConfigFromDisk(): Promise<LlmConfig | null> {
  const existing = loadLlmConfig();
  if (existing) return existing;
  try {
    const fromDisk = await invoke<LlmConfig | null>("ai_config_load");
    if (fromDisk && fromDisk.api_key) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(fromDisk));
      return fromDisk;
    }
  } catch {}
  return null;
}

export interface LlmMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LlmCallOptions {
  json_object?: boolean;
  max_tokens?: number;
}

export interface LlmResponse {
  text: string;
  input_tokens?: number;
  output_tokens?: number;
}

/**
 * 调用 LLM(后端 reqwest)。
 */
export async function callLlm(
  config: LlmConfig,
  messages: LlmMessage[],
  opts: LlmCallOptions = {}
): Promise<LlmResponse> {
  return await invoke<LlmResponse>("dbg_llm_call", {
    req: { config, messages, opts },
  });
}

/** 测试连接 — 让模型简短回答 */
export async function testLlmConnection(config: LlmConfig): Promise<string> {
  const r = await callLlm(
    config,
    [
      { role: "system", content: "Reply with exactly OK and nothing else." },
      { role: "user", content: "ping" },
    ],
    { max_tokens: 32 }
  );
  return r.text.trim();
}
