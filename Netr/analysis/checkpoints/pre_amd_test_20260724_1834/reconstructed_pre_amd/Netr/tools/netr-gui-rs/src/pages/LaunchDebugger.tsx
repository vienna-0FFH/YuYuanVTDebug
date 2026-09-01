import { useState } from "react";
import { Bug, ExternalLink, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { invoke } from "@tauri-apps/api/core";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { errMsg } from "@/debugger/ipc";

interface OpenSession {
  label: string;
  openedAt: number;
}

export default function LaunchDebugger() {
  const [busy, setBusy] = useState(false);
  const [sessions, setSessions] = useState<OpenSession[]>([]);

  async function open() {
    setBusy(true);
    try {
      const label = await invoke<string>("dbg_open_window");
      setSessions((prev) => [...prev, { label, openedAt: Date.now() }]);
      toast.success(`调试器窗口已打开 (${label}),在新窗口里选择目标进程`);
    } catch (e: unknown) {
      toast.error(`打开失败: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="内置调试器"
      />

      <Card className="card-hover card-steel relative overflow-hidden">
        <div className="bg-steel-soft pointer-events-none absolute inset-0" />
        <CardHeader className="relative pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Bug className="h-4 w-4 text-primary" /> 打开调试器窗口
          </CardTitle>
          <CardDescription>
            点击下方按钮新开窗口。默认 Native 模式，无驱动也可使用；驱动设备已连接时可在窗口顶部切换 VT 模式。
          </CardDescription>
        </CardHeader>
        <CardContent className="relative">
          <Button onClick={open} disabled={busy} size="lg" className="w-full">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ExternalLink className="h-4 w-4" />}
            {busy ? "打开中..." : "打开新调试器窗口"}
          </Button>
        </CardContent>
      </Card>

      {sessions.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">本次会话已开 · {sessions.length}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {sessions.map((s) => (
                <div key={s.label} className="flex items-center justify-between rounded-md border bg-card/40 px-3 py-2 text-sm">
                  <div className="flex items-center gap-3">
                    <div className="flex h-7 w-7 items-center justify-center rounded bg-primary/10 text-primary">
                      <Bug className="h-3.5 w-3.5" />
                    </div>
                    <span className="font-mono">{s.label}</span>
                    <span className="text-xs text-muted-foreground">
                      {new Date(s.openedAt).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">能力(P15 CE 风格完整版)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <CapDone label="Native 会话使用 Windows 原生进程/线程调试链，不依赖驱动" />
          <CapDone label="VT 会话附加时登记调试器保护并绑定目标，启用 VT 内存与无痕断点能力" />
          <CapDone label="主界面 = 内存扫描器(上)+ 监视表(下),CE 风格" />
          <CapDone label="监视表:多类型、freeze 锁定值(后台 10Hz 写回)、双击改值/标签" />
          <CapDone label="按需打开「内存视图」工具(反汇编/Hex/寄存器/栈/软断 5 合 1 tab)" />
          <CapDone label="按需打开「硬件断点」工具,DR0-3 走驱动 hwbp IOCTL,无痕" />
          <CapDone label="反汇编 iced-x86,行内设/清软断 + RIP 高亮 + 双击跟随 Hex" />
          <CapDone label="Hex 视图 + 双击改字节" />
          <CapDone label="寄存器 RAX..R15/RIP/RFLAGS 读改" />
          <CapDone label="栈 64 项 qword,点行跳到值" />
          <CapDone label="扫描器:12 类型 / 10 对比 / 范围限定 / 命中→监视表" />
        </CardContent>
      </Card>
    </div>
  );
}

function CapDone({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-1.5 w-1.5 rounded-full bg-success" />
      <span>{label}</span>
    </div>
  );
}
