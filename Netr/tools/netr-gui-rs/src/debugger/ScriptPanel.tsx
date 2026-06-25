import { useState } from "react";
import { Play, Loader2, FileCode2, Wrench } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSession } from "./sessionStore";
import { evalExpression } from "./expr";
import { cn } from "@/lib/utils";
import { errMsg } from "./ipc";

interface LuaRunResult { output: string; error?: string | null; }
interface AsmResult { bytes: number[]; original: number[]; size: number; }

type Sub = "lua" | "asm";

const LUA_EXAMPLE = `-- 内置 API:
--   read_i32/read_i64/read_u32/read_f32/read_f64/read_ptr/read_bytes(pid, addr [, n])
--   write_i32/write_u32/write_i64/write_u64/write_f32/write_f64/write_bytes
--   find_pattern(pid, "AA BB ? CC")
--   log(...), hex(n)
-- 全局: PID
local addr = find_pattern(PID, "48 83 ec 28 e8")
if addr then
  log("hit:", hex(addr))
  log("first 4 bytes as i32:", read_i32(PID, addr))
else
  log("not found")
end
`;

const ASM_EXAMPLE = `; 暂支持: nop / ret / int3 / ud2 / cli / sti
; 复杂指令请用 Lua write_bytes 写字节
nop
nop
ret
`;

export function ScriptPanel() {
  const { pid, ctx } = useSession();
  const [sub, setSub] = useState<Sub>("lua");

  // lua state
  const [luaSrc, setLuaSrc] = useState(LUA_EXAMPLE);
  const [luaOut, setLuaOut] = useState("");
  const [busy, setBusy] = useState(false);

  // asm state
  const [asmSrc, setAsmSrc] = useState(ASM_EXAMPLE);
  const [asmAddr, setAsmAddr] = useState("");
  const [asmRes, setAsmRes] = useState<AsmResult | null>(null);

  async function runLua() {
    if (!pid) return toast.error("未附加");
    setBusy(true);
    setLuaOut("");
    try {
      const r = await invoke<LuaRunResult>("dbg_lua_run", { pid, script: luaSrc });
      let out = r.output ?? "";
      if (r.error) out += `\n[error] ${r.error}`;
      setLuaOut(out);
    } catch (e) {
      setLuaOut(`[invoke error] ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function assemble(apply: boolean) {
    if (!pid) return toast.error("未附加");
    const t = asmAddr.trim();
    if (!t) return toast.error("先填写要 patch 的地址");
    setBusy(true);
    try {
      const addr = await evalExpression(t, { pid, ctx });
      const r = await invoke<AsmResult>("dbg_assemble_patch", {
        pid, address: Number(addr), source: asmSrc, apply,
      });
      setAsmRes(r);
      toast.success(apply ? `已写入 ${r.size} 字节` : `编译成功 ${r.size} 字节(未写入)`);
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function revert() {
    if (!pid || !asmRes || !asmRes.original || asmRes.original.length === 0)
      return toast.error("无原字节备份");
    const t = asmAddr.trim();
    if (!t) return;
    setBusy(true);
    try {
      const addr = await evalExpression(t, { pid, ctx });
      // 直接调 dbg_write_memory 还原
      await invoke<void>("dbg_write_memory", {
        pid, address: Number(addr), bytes: asmRes.original,
      });
      toast.success("已还原原字节");
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <FileCode2 className="h-3.5 w-3.5 text-primary" />
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">脚本 / 汇编</span>
        <div className="flex h-6 rounded-md border border-border bg-background p-0.5">
          {(["lua", "asm"] as Sub[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setSub(t)}
              className={cn(
                "rounded-sm px-2 text-[11px] font-medium transition-colors",
                sub === t
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              {t === "lua" ? "Lua" : "Assembler"}
            </button>
          ))}
        </div>
        <div className="ml-auto">
          {sub === "lua" ? (
            <Button size="sm" onClick={() => void runLua()} disabled={busy} className="h-6 px-2">
              {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />} 运行
            </Button>
          ) : (
            <div className="flex items-center gap-1">
              <Input
                value={asmAddr}
                onChange={(e) => setAsmAddr(e.target.value)}
                placeholder="patch 地址"
                className="h-6 w-44 font-mono text-xs"
              />
              <Button size="sm" variant="outline" onClick={() => void assemble(false)} disabled={busy} className="h-6 px-2">
                编译
              </Button>
              <Button size="sm" onClick={() => void assemble(true)} disabled={busy} className="h-6 px-2">
                <Wrench className="h-3 w-3" /> 应用
              </Button>
              <Button size="sm" variant="ghost" onClick={() => void revert()} disabled={busy || !asmRes} className="h-6 px-2">
                还原
              </Button>
            </div>
          )}
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        {sub === "lua" ? (
          <>
            <textarea
              value={luaSrc}
              onChange={(e) => setLuaSrc(e.target.value)}
              spellCheck={false}
              className="min-h-0 flex-1 resize-none border-b border-border bg-background p-2 font-mono text-[11px] outline-none"
            />
            <pre className="min-h-[100px] max-h-[40%] overflow-auto bg-card/40 p-2 text-[11px] font-mono whitespace-pre-wrap">
              {luaOut || <span className="text-muted-foreground">—</span>}
            </pre>
          </>
        ) : (
          <>
            <textarea
              value={asmSrc}
              onChange={(e) => setAsmSrc(e.target.value)}
              spellCheck={false}
              className="min-h-0 flex-1 resize-none border-b border-border bg-background p-2 font-mono text-[11px] outline-none"
            />
            <div className="min-h-[80px] overflow-auto bg-card/40 p-2 font-mono text-[10px]">
              {asmRes ? (
                <>
                  <div className="text-muted-foreground">新字节 ({asmRes.size}):</div>
                  <div className="text-emerald-400 break-all">{asmRes.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ")}</div>
                  <div className="mt-1 text-muted-foreground">原字节备份:</div>
                  <div className="text-amber-400 break-all">{asmRes.original.map((b) => b.toString(16).padStart(2, "0")).join(" ")}</div>
                </>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
