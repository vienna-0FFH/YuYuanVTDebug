import { useState } from "react";
import { ArrowDownToLine, ArrowUpFromLine, Plus, Minus } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { ProcessPicker } from "@/components/common/ProcessPicker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { memoryIpc, type ProcessInfo } from "@/ipc";

const PAGE_READWRITE = 0x04;

export default function Memory() {
  const [target, setTarget] = useState<ProcessInfo | null>(null);
  const [addrHex, setAddrHex] = useState("");
  const [size, setSize] = useState("64");
  const [readBytes, setReadBytes] = useState<number[] | null>(null);
  const [writeHex, setWriteHex] = useState("");
  const [allocSize, setAllocSize] = useState("4096");
  const [allocAddr, setAllocAddr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function parsePid(): number | null {
    if (!target) {
      toast.error("请先选择目标进程");
      return null;
    }
    return target.pid;
  }

  function parseAddr(s: string): bigint | null {
    try {
      const v = s.trim().toLowerCase().replace(/^0x/, "");
      if (!/^[0-9a-f]+$/.test(v)) throw new Error();
      return BigInt("0x" + v);
    } catch {
      toast.error("地址必须是 16 进制");
      return null;
    }
  }

  function parseHexBytes(s: string): number[] | null {
    const tokens = s.trim().split(/[\s,]+/).filter(Boolean);
    const out: number[] = [];
    for (const t of tokens) {
      const v = parseInt(t, 16);
      if (Number.isNaN(v) || v < 0 || v > 255) {
        toast.error(`无效十六进制字节: ${t}`);
        return null;
      }
      out.push(v);
    }
    return out;
  }

  async function onRead() {
    const p = parsePid();
    if (p === null) return;
    const a = parseAddr(addrHex);
    if (a === null) return;
    const sz = Number(size);
    if (!Number.isFinite(sz) || sz <= 0 || sz > 4096) {
      toast.error("Size 必须 1~4096");
      return;
    }
    setBusy(true);
    try {
      const data = await memoryIpc.read(p, a, sz);
      setReadBytes(data);
      toast.success(`读取 ${data.length} 字节`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`读取失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onWrite() {
    const p = parsePid();
    if (p === null) return;
    const a = parseAddr(addrHex);
    if (a === null) return;
    const bytes = parseHexBytes(writeHex);
    if (bytes === null || bytes.length === 0) return;
    setBusy(true);
    try {
      await memoryIpc.write(p, a, bytes);
      toast.success(`写入 ${bytes.length} 字节`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`写入失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onAlloc() {
    const p = parsePid();
    if (p === null) return;
    const sz = Number(allocSize);
    if (!Number.isFinite(sz) || sz <= 0) {
      toast.error("Size 必须 > 0");
      return;
    }
    setBusy(true);
    try {
      const addr = await memoryIpc.alloc(p, sz, PAGE_READWRITE);
      const hex = "0x" + addr.toString(16);
      setAllocAddr(hex);
      toast.success(`分配 ${sz} 字节 @ ${hex}`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`分配失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onFree() {
    const p = parsePid();
    if (p === null) return;
    if (!allocAddr) {
      toast.error("没有可释放的地址");
      return;
    }
    setBusy(true);
    try {
      await memoryIpc.free(p, BigInt(allocAddr));
      toast.success("已释放");
      setAllocAddr(null);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`释放失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="内存读写"
      />

      <Card>
        <CardHeader>
          <CardTitle>目标进程</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1.5">
            <Label>进程</Label>
            <ProcessPicker value={target} onChange={setTarget} disabled={busy} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>读 / 写</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="mem-addr">地址 (hex)</Label>
              <Input id="mem-addr" value={addrHex} onChange={(e) => setAddrHex(e.target.value)} placeholder="7FF6A0000000" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mem-size">Size</Label>
              <Input id="mem-size" type="number" value={size} onChange={(e) => setSize(e.target.value)} />
            </div>
          </div>

          <div className="flex gap-2">
            <Button onClick={onRead} disabled={busy} variant="default">
              <ArrowDownToLine className="h-4 w-4" /> 读
            </Button>
            <Button onClick={onWrite} disabled={busy} variant="outline">
              <ArrowUpFromLine className="h-4 w-4" /> 写
            </Button>
          </div>

          <div className="space-y-2">
            <Label htmlFor="mem-write">写入字节 (hex, 空格分隔)</Label>
            <Input
              id="mem-write"
              value={writeHex}
              onChange={(e) => setWriteHex(e.target.value)}
              placeholder="48 8B 05 00 00 00 00"
            />
          </div>

          {readBytes ? (
            <div className="space-y-2">
              <Label>已读字节</Label>
              <pre className="max-h-48 overflow-auto rounded bg-muted p-2 font-mono text-xs">
                {hexdump(readBytes, BigInt("0x" + (addrHex.replace(/^0x/, "") || "0")))}
              </pre>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>分配 / 释放</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="alloc-size">Size (bytes)</Label>
            <Input id="alloc-size" type="number" value={allocSize} onChange={(e) => setAllocSize(e.target.value)} />
          </div>
          <div className="flex gap-2">
            <Button onClick={onAlloc} disabled={busy} variant="default">
              <Plus className="h-4 w-4" /> 分配
            </Button>
            <Button onClick={onFree} disabled={busy || !allocAddr} variant="outline">
              <Minus className="h-4 w-4" /> 释放
            </Button>
          </div>
          {allocAddr ? (
            <div className="text-sm text-muted-foreground">
              分配地址: <span className="font-mono text-foreground">{allocAddr}</span>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

function hexdump(bytes: number[], base: bigint): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const addr = (base + BigInt(i)).toString(16).padStart(16, "0").toUpperCase();
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${addr}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join("\n");
}
