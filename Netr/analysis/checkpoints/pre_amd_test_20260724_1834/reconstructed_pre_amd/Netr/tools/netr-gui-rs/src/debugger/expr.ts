import { dbgIpc } from "./ipc";
import type { ThreadContextView } from "./ipc";

export interface ExprCtx {
  pid: number;
  ctx: ThreadContextView | null;
}

const REG_NAMES = [
  "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
  "r8","r9","r10","r11","r12","r13","r14","r15",
  "rip","rflags",
] as const;

function regValue(ctx: ThreadContextView | null, name: string): bigint | null {
  if (!ctx) return null;
  const r = ctx as unknown as Record<string, number | bigint | undefined>;
  const v = r[name];
  if (v === undefined) return null;
  return typeof v === "bigint" ? v : BigInt(v);
}

let MODULE_CACHE: { pid: number; mods: { name: string; base: bigint; size: bigint }[] } | null = null;
async function getModules(pid: number) {
  if (MODULE_CACHE && MODULE_CACHE.pid === pid) return MODULE_CACHE.mods;
  const raw = await dbgIpc.listModules(pid);
  const mods = raw.map((m) => ({
    name: m.name.toLowerCase(),
    base: BigInt(m.base),
    size: BigInt(m.size ?? 0),
  }));
  MODULE_CACHE = { pid, mods };
  return mods;
}

/** 清模块缓存(进程变化或附加新进程时调) */
export function clearExprModuleCache() {
  MODULE_CACHE = null;
}

function parseIntFlexible(s: string): bigint | null {
  s = s.trim();
  if (!s) return null;
  try {
    if (s.startsWith("0x") || s.startsWith("0X")) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    if (/^[0-9a-fA-F]+$/.test(s)) return BigInt("0x" + s);
  } catch {
    /* fall through */
  }
  return null;
}

/**
 * 解析地址表达式,返回 bigint。
 * 支持:
 *   - 16/10 进制 (123 / 0x123 / abc)
 *   - 寄存器 (rax, rip, rsp ...)
 *   - 模块基址 (kernel32.dll, ntdll, user32.dll+0x1234)
 *   - 简单加减 (rax+10, rsp-8)
 *   - 单层间接 ([rax], [rsp+8], [kernel32+0x1234]) — 需要读 8 字节
 */
export async function evalExpression(input: string, ec: ExprCtx): Promise<bigint> {
  const text = input.trim();
  if (!text) throw new Error("空表达式");

  // 单层间接 [...]
  if (text.startsWith("[") && text.endsWith("]")) {
    const inner = text.slice(1, -1);
    const addr = await evalExpression(inner, ec);
    const r = await dbgIpc.readMemory(ec.pid, Number(addr), 8);
    if (!r.bytes || r.bytes.length < 8) throw new Error("无法读取间接地址内容");
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(r.bytes[i]);
    return v;
  }

  // 找加减分割
  const parts = splitTopLevel(text);
  if (parts.length === 0) throw new Error("无效表达式");

  // 第一段:基址
  let acc = await evalAtom(parts[0].token, ec);
  // 后续:操作 + 操作数
  for (let i = 1; i < parts.length; i++) {
    const op = parts[i].op;
    const v = await evalAtom(parts[i].token, ec);
    if (op === "+") acc = acc + v;
    else if (op === "-") acc = acc - v;
    else throw new Error(`不支持的运算符 ${op}`);
  }
  return acc;
}

interface Part {
  op: "+" | "-" | "";
  token: string;
}
function splitTopLevel(text: string): Part[] {
  const out: Part[] = [];
  let depth = 0;
  let cur = "";
  let op: "+" | "-" | "" = "";
  for (const ch of text) {
    if (ch === "[") {
      depth++;
      cur += ch;
    } else if (ch === "]") {
      depth--;
      cur += ch;
    } else if ((ch === "+" || ch === "-") && depth === 0 && cur.trim()) {
      out.push({ op, token: cur.trim() });
      op = ch;
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push({ op, token: cur.trim() });
  return out;
}

async function evalAtom(tok: string, ec: ExprCtx): Promise<bigint> {
  const t = tok.trim();
  if (!t) throw new Error("空操作数");

  // 间接
  if (t.startsWith("[") && t.endsWith("]")) {
    return evalExpression(t, ec);
  }

  // 寄存器
  const lower = t.toLowerCase();
  if ((REG_NAMES as readonly string[]).includes(lower)) {
    const v = regValue(ec.ctx, lower);
    if (v === null) throw new Error(`无法读取寄存器 ${lower} (线程未挂起?)`);
    return v;
  }

  // 整数字面量
  const lit = parseIntFlexible(t);
  if (lit !== null) return lit;

  // 模块名 — 整段就是模块名,或者只剩纯字符,作模块基址
  if (ec.pid > 0) {
    const mods = await getModules(ec.pid);
    const target = lower.endsWith(".dll") || lower.endsWith(".exe") ? lower : `${lower}.dll`;
    const direct = mods.find((m) => m.name === lower);
    if (direct) return direct.base;
    const dllFallback = mods.find((m) => m.name === target);
    if (dllFallback) return dllFallback.base;
    // 前缀匹配(kernel32 → kernel32.dll)
    const prefix = mods.find((m) => m.name.startsWith(lower + "."));
    if (prefix) return prefix.base;
  }

  throw new Error(`无法解析: ${tok}`);
}

/** 格式化地址 — 大写,16 位补 0 */
export function formatAddress(a: bigint): string {
  const s = a.toString(16).toUpperCase();
  return s.padStart(16, "0");
}
