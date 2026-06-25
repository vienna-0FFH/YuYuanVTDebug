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
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (!open) return;
    const c = loadLlmConfig();
    if (c) {
      setProvider(c.provider);
      setBaseUrl(c.base_url);
      setApiKey(c.api_key);
      setModel(c.model);
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
    return { provider, base_url: baseUrl, api_key: apiKey, model };
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
