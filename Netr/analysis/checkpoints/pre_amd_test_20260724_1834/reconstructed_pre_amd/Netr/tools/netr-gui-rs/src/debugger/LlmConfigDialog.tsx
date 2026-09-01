import { useEffect, useState } from "react";
import { Bot, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  loadLlmConfig, saveLlmConfig, clearLlmConfig, testLlmConnection,
  DEFAULT_BASE_URLS, type LlmConfig, type LlmProvider,
} from "@/lib/llm";
import { errMsg } from "./ipc";

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

export function LlmConfigDialog({ open, onOpenChange }: Props) {
  const [provider, setProvider] = useState<LlmProvider>("openai");
  const [baseUrl, setBaseUrl] = useState(DEFAULT_BASE_URLS.openai);
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("gpt-4o-mini");
  const [reasoningEffort, setReasoningEffort] = useState<LlmConfig["reasoning_effort"] | "">("");
  const [contextTokens, setContextTokens] = useState("");
  const [inputTokens, setInputTokens] = useState("");
  const [outputTokens, setOutputTokens] = useState("");
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (!open) return;
    const c = loadLlmConfig();
    if (c) {
      setProvider(c.provider);
      setBaseUrl(c.base_url);
      setApiKey(c.api_key);
      setModel(c.model);
      setReasoningEffort(c.reasoning_effort ?? "");
      setContextTokens(c.context_tokens?.toString() ?? "");
      setInputTokens(c.input_tokens?.toString() ?? "");
      setOutputTokens(c.output_tokens?.toString() ?? "");
    }
  }, [open]);

  function changeProvider(p: LlmProvider) {
    setProvider(p);
    if (!baseUrl || baseUrl === DEFAULT_BASE_URLS.openai || baseUrl === DEFAULT_BASE_URLS.anthropic) {
      setBaseUrl(DEFAULT_BASE_URLS[p]);
    }
    if (!model || ["gpt-4o-mini", "gpt-4o", "claude-3-5-sonnet-latest"].includes(model)) {
      setModel(p === "openai" ? "gpt-4o-mini" : "claude-3-5-sonnet-latest");
    }
  }

  function build(): LlmConfig {
    const previous = loadLlmConfig();
    const parseLimit = (value: string) => {
      const parsed = Number(value.trim());
      return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
    };
    return {
      ...previous,
      provider,
      base_url: baseUrl,
      api_key: apiKey,
      model,
      reasoning_effort: reasoningEffort || undefined,
      context_tokens: parseLimit(contextTokens),
      input_tokens: parseLimit(inputTokens),
      output_tokens: parseLimit(outputTokens),
    };
  }

  async function onTest() {
    if (!apiKey) return toast.error("先填 API key");
    setTesting(true);
    try {
      const r = await testLlmConnection(build());
      toast.success(`连接 OK: ${r.slice(0, 64)}`);
    } catch (e) {
      toast.error(`连接失败: ${errMsg(e)}`);
    } finally {
      setTesting(false);
    }
  }

  function onSave() {
    if (!apiKey || !model) return toast.error("API key / 模型必填");
    saveLlmConfig(build());
    toast.success("已保存");
    onOpenChange(false);
  }

  function onClear() {
    clearLlmConfig();
    setApiKey("");
    toast.success("已清除");
  }

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={<span className="flex items-center gap-2"><Bot className="h-4 w-4" /> AI 配置</span>}
      widthClass="max-w-md"
    >
      <div className="space-y-3 px-5 py-4">
        <div className="space-y-1">
          <Label className="text-xs">协议</Label>
          <div className="flex h-7 rounded-md border border-input bg-background p-0.5">
            {(["openai", "anthropic"] as LlmProvider[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => changeProvider(p)}
                className={`flex-1 rounded-sm px-2 text-xs font-medium transition-colors ${
                  provider === p
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent"
                }`}
              >
                {p === "openai" ? "OpenAI 兼容" : "Anthropic"}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-1">
          <Label className="text-xs">Base URL</Label>
          <Input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            className="h-7 font-mono text-xs"
          />
        </div>

        <div className="space-y-1">
          <Label className="text-xs">API Key</Label>
          <Input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="h-7 font-mono text-xs"
            placeholder="sk-..."
          />
        </div>

        <div className="space-y-1">
          <Label className="text-xs">模型</Label>
          <Input
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="h-7 font-mono text-xs"
          />
          <div className="text-[10px] text-muted-foreground">
            推荐:OpenAI = <code>gpt-4o</code> / <code>gpt-5</code>;Anthropic = <code>claude-3-5-sonnet-latest</code> / <code>claude-opus-4-7</code>。
          </div>
        </div>

        <div className="space-y-1">
          <Label className="text-xs">Reasoning effort</Label>
          <select
            value={reasoningEffort}
            onChange={(event) => setReasoningEffort(event.target.value as LlmConfig["reasoning_effort"] | "")}
            className="h-7 w-full rounded-md border border-input bg-background px-2 font-mono text-xs"
          >
            <option value="">Auto / omit</option>
            <option value="none">none</option>
            <option value="minimal">minimal</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="xhigh">xhigh</option>
            <option value="max">max</option>
          </select>
          <div className="text-[10px] text-muted-foreground">
            GPT-5.6-sol supports none/low/medium/high/xhigh/max; unsupported selections fail before sending.
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <div className="space-y-1">
            <Label className="text-[10px]">Context tokens</Label>
            <Input value={contextTokens} onChange={(event) => setContextTokens(event.target.value)} placeholder="auto" className="h-7 font-mono text-xs" />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px]">Input tokens</Label>
            <Input value={inputTokens} onChange={(event) => setInputTokens(event.target.value)} placeholder="auto" className="h-7 font-mono text-xs" />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px]">Output tokens</Label>
            <Input value={outputTokens} onChange={(event) => setOutputTokens(event.target.value)} placeholder="auto" className="h-7 font-mono text-xs" />
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" size="sm" onClick={onClear}>清除</Button>
          <Button variant="outline" size="sm" onClick={() => void onTest()} disabled={testing}>
            {testing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "测试连接"}
          </Button>
          <Button size="sm" onClick={onSave}>保存</Button>
        </div>
      </div>
    </Dialog>
  );
}
