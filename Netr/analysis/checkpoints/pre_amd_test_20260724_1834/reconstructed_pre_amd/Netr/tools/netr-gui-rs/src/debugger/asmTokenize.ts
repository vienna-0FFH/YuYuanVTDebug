/**
 * 反汇编指令文本 tokenize — 给 DisasmRow 高亮用.
 *
 * iced-x86 给出的 text 形如:
 *   "mov rax,qword ptr [rip+0x12345]"
 *   "call qword ptr [rax+0x30]"
 *   "jne short 0x140001234"
 *   "lea rcx,[rbx+rcx*4+0x20]"
 *
 * 我们 tokenize 成几类 token, 渲染时套不同 className.
 */

export type TokenKind =
  | "mnemonic"
  | "register"
  | "number"
  | "memory"
  | "punct"
  | "keyword"   // "qword ptr" / "short" / "rep" 等
  | "address"   // 0x140001234 这种全 hex 地址
  | "comment"
  | "ws"
  | "text";

export interface AsmToken {
  kind: TokenKind;
  text: string;
}

// x86-64 全寄存器 (含 SSE/AVX 缩写). 用 Set 加速.
const REGISTERS = new Set([
  // 64
  "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
  "r8","r9","r10","r11","r12","r13","r14","r15",
  "rip",
  // 32
  "eax","ebx","ecx","edx","esi","edi","ebp","esp",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
  // 16
  "ax","bx","cx","dx","si","di","bp","sp",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
  // 8
  "al","bl","cl","dl","sil","dil","bpl","spl",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
  "ah","bh","ch","dh",
  // segment
  "cs","ds","es","fs","gs","ss",
  // x87
  "st0","st1","st2","st3","st4","st5","st6","st7","st",
  // mm/xmm/ymm/zmm
  ...Array.from({ length: 32 }, (_, i) => `xmm${i}`),
  ...Array.from({ length: 32 }, (_, i) => `ymm${i}`),
  ...Array.from({ length: 32 }, (_, i) => `zmm${i}`),
  ...Array.from({ length: 8 }, (_, i) => `mm${i}`),
  // control / debug
  "cr0","cr2","cr3","cr4","cr8","dr0","dr1","dr2","dr3","dr6","dr7",
]);

// 关键字 / 前缀
const KEYWORDS = new Set([
  "byte","word","dword","qword","tword","oword","xmmword","ymmword","zmmword","fword","ptr",
  "short","near","far","offset",
  "lock","rep","repe","repne","repz","repnz","bnd",
]);

/** 跳转 / 调用指令 — 高亮成 control */
export const CONTROL_MNEMONICS = new Set([
  "jmp","jmpf","call","callf","ret","retn","retf","iret","iretq",
  "je","jne","jz","jnz","ja","jae","jb","jbe","jc","jnc","jg","jge","jl","jle",
  "jo","jno","js","jns","jp","jnp","jpe","jpo","jcxz","jecxz","jrcxz",
  "loop","loope","loopne","loopz","loopnz",
  "int","int3","into","syscall","sysret","sysenter","sysexit","ud2",
]);

const ARITH_MNEMONICS = new Set([
  "add","sub","adc","sbb","imul","mul","idiv","div","inc","dec","neg",
  "and","or","xor","not","shl","shr","sal","sar","rol","ror","rcl","rcr",
  "test","cmp","bt","bts","btr","btc","bsf","bsr","popcnt",
]);

const DATA_MNEMONICS = new Set([
  "mov","movzx","movsx","movsxd","movabs","lea","push","pop","xchg","cmpxchg","xadd",
  "cmovz","cmovnz","cmove","cmovne","cmovg","cmovge","cmovl","cmovle",
  "cmova","cmovae","cmovb","cmovbe","cmovs","cmovns",
  "pxor","movaps","movups","movdqa","movdqu","movss","movsd","movd","movq",
  "vmovaps","vmovups","vmovdqa","vmovdqu","vmovss","vmovsd",
]);

const FLOAT_MNEMONICS = new Set([
  "addss","subss","mulss","divss","minss","maxss","sqrtss","cmpss","ucomiss","comiss",
  "addsd","subsd","mulsd","divsd","minsd","maxsd","sqrtsd","cmpsd","ucomisd","comisd",
  "addps","subps","mulps","divps","mulps","cvtss2sd","cvtsd2ss","cvttss2si","cvttsd2si",
  "fld","fst","fstp","fadd","fsub","fmul","fdiv","fcom","fcomp","fxch",
]);

export function classifyMnemonic(m: string): "control" | "arith" | "data" | "float" | "other" {
  const k = m.toLowerCase();
  if (CONTROL_MNEMONICS.has(k)) return "control";
  if (DATA_MNEMONICS.has(k)) return "data";
  if (ARITH_MNEMONICS.has(k)) return "arith";
  if (FLOAT_MNEMONICS.has(k)) return "float";
  return "other";
}

const HEX_RE = /^0x[0-9a-fA-F]+$/;
const ADDR_LIKE = /^0x[0-9a-fA-F]{4,}$/;
const DEC_RE = /^-?[0-9]+$/;

/** 单条指令文本 → token 数组. mnemonic 单独提取(第一个 word). */
export function tokenizeAsm(text: string): AsmToken[] {
  const out: AsmToken[] = [];
  // 拆 comment(分号后)
  const semi = text.indexOf(";");
  const body = semi >= 0 ? text.slice(0, semi) : text;
  const comment = semi >= 0 ? text.slice(semi) : "";

  // 先分出 mnemonic + 剩余操作数
  const m = body.match(/^(\s*)([a-zA-Z][a-zA-Z0-9]*)(.*)$/);
  if (!m) {
    out.push({ kind: "text", text: body });
  } else {
    if (m[1]) out.push({ kind: "ws", text: m[1] });
    out.push({ kind: "mnemonic", text: m[2] });
    if (m[3]) out.push(...tokenizeOperands(m[3]));
  }
  if (comment) out.push({ kind: "comment", text: comment });
  return out;
}

function tokenizeOperands(s: string): AsmToken[] {
  const out: AsmToken[] = [];
  let i = 0;
  let memDepth = 0;     // [ 深度
  let buf = "";
  const flush = (kind: TokenKind) => { if (buf) { out.push({ kind, text: buf }); buf = ""; } };

  while (i < s.length) {
    const c = s[i];
    if (memDepth > 0) {
      // 内存块: 整段一起标 memory, 但跟踪 [ 配对
      buf += c;
      if (c === "[") memDepth++;
      else if (c === "]") {
        memDepth--;
        if (memDepth === 0) {
          flush("memory");
        }
      }
      i++;
      continue;
    }
    if (c === "[") {
      flush("text");
      memDepth = 1;
      buf = "[";
      i++;
      continue;
    }
    if (c === " " || c === "\t") {
      flush("text");
      // 收集连续空白
      let ws = c; i++;
      while (i < s.length && (s[i] === " " || s[i] === "\t")) { ws += s[i]; i++; }
      out.push({ kind: "ws", text: ws });
      continue;
    }
    if (c === "," || c === ":" || c === "+" || c === "-" || c === "*") {
      flush("text");
      out.push({ kind: "punct", text: c });
      i++;
      continue;
    }
    // 单词 / 数字
    if (/[a-zA-Z_0-9.]/.test(c)) {
      let w = ""; let j = i;
      while (j < s.length && /[a-zA-Z_0-9.]/.test(s[j])) { w += s[j]; j++; }
      const lower = w.toLowerCase();
      // 数字判定
      if (HEX_RE.test(w) || DEC_RE.test(w)) {
        const kind: TokenKind = ADDR_LIKE.test(w) ? "address" : "number";
        out.push({ kind, text: w });
      } else if (REGISTERS.has(lower)) {
        out.push({ kind: "register", text: w });
      } else if (KEYWORDS.has(lower)) {
        out.push({ kind: "keyword", text: w });
      } else {
        out.push({ kind: "text", text: w });
      }
      i = j;
      continue;
    }
    // 其它字符
    out.push({ kind: "text", text: c });
    i++;
  }
  flush("text");
  return out;
}

/** 把内存块 [rip+0x12...] 再细分一次, 让里面寄存器/数字也高亮 */
export function tokenizeMemoryInner(text: string): AsmToken[] {
  if (!text.startsWith("[") || !text.endsWith("]")) {
    return [{ kind: "memory", text }];
  }
  const inner = text.slice(1, -1);
  const inside = tokenizeOperands(inner);
  return [
    { kind: "punct", text: "[" },
    ...inside,
    { kind: "punct", text: "]" },
  ];
}
