import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Search, X, Loader2, MousePointerClick } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog } from "@/components/ui/dialog";
import { systemIpc, type ProcessInfo } from "@/ipc";
import { cn } from "@/lib/utils";

interface Props {
  value: ProcessInfo | null;
  onChange: (p: ProcessInfo | null) => void;
  placeholder?: string;
  hideSystem?: boolean;
  disabled?: boolean;
}

const SYS_NAMES = new Set([
  "System",
  "Registry",
  "smss.exe",
  "csrss.exe",
  "wininit.exe",
  "services.exe",
  "lsass.exe",
  "winlogon.exe",
  "Memory Compression",
]);

export function ProcessPicker({
  value,
  onChange,
  placeholder = "选择进程...",
  hideSystem = true,
  disabled,
}: Props) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <div className="flex gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={() => setOpen(true)}
          className={cn(
            "flex h-9 flex-1 items-center gap-2 rounded-md border border-input bg-background px-3 text-left text-sm transition-colors",
            "hover:border-ring/50 hover:bg-accent/40 disabled:cursor-not-allowed disabled:opacity-50"
          )}
        >
          <MousePointerClick className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          {value ? (
            <>
              <span className="font-mono text-xs text-muted-foreground">{value.pid}</span>
              <span className="truncate font-medium">{value.name}</span>
              <span className="ml-auto truncate text-[11px] text-muted-foreground">{value.path}</span>
            </>
          ) : (
            <span className="text-muted-foreground">{placeholder}</span>
          )}
        </button>
        {value && (
          <Button
            variant="ghost"
            size="icon"
            disabled={disabled}
            onClick={() => onChange(null)}
            aria-label="清除选择"
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      <ProcessPickerDialog
        open={open}
        onClose={() => setOpen(false)}
        value={value}
        onPick={(p) => {
          onChange(p);
          setOpen(false);
        }}
        hideSystem={hideSystem}
      />
    </>
  );
}

function ProcessPickerDialog({
  open,
  onClose,
  value,
  onPick,
  hideSystem,
}: {
  open: boolean;
  onClose: () => void;
  value: ProcessInfo | null;
  onPick: (p: ProcessInfo) => void;
  hideSystem: boolean;
}) {
  const [list, setList] = useState<ProcessInfo[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const data = await systemIpc.listProcesses();
      setList(data);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`枚举进程失败: ${msg}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (open) {
      setFilter("");
      void load();
    }
  }, [open]);

  const filtered = useMemo(() => {
    let r = list;
    if (hideSystem) r = r.filter((p) => p.pid > 4 && !SYS_NAMES.has(p.name));
    const q = filter.trim().toLowerCase();
    if (q) {
      r = r.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          String(p.pid).includes(q) ||
          p.path.toLowerCase().includes(q)
      );
    }
    return r;
  }, [list, filter, hideSystem]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="选择进程"
      description={`共 ${filtered.length} / ${list.length} 个,可按名称 / PID / 路径搜索`}
      widthClass="max-w-3xl"
    >
      <div className="flex h-[65vh] flex-col gap-3 p-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="搜索…"
              className="pl-8"
              autoFocus
            />
          </div>
          <Button variant="outline" onClick={load} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            刷新
          </Button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto rounded-md border bg-background/40">
          {/* 表头 */}
          <div className="sticky top-0 z-10 flex gap-3 border-b bg-card/95 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground backdrop-blur">
            <span className="w-16">PID</span>
            <span className="w-52">进程名</span>
            <span className="flex-1">路径</span>
          </div>

          {filtered.length === 0 ? (
            <div className="flex h-32 items-center justify-center text-sm text-muted-foreground">
              {loading ? "枚举中..." : "没有匹配的进程"}
            </div>
          ) : (
            <div className="divide-y divide-border/60">
              {filtered.map((p) => {
                const selected = value?.pid === p.pid;
                return (
                  <button
                    key={p.pid}
                    type="button"
                    onClick={() => onPick(p)}
                    onDoubleClick={() => onPick(p)}
                    className={cn(
                      "flex w-full items-center gap-3 px-3 py-2 text-left text-xs transition-colors",
                      selected ? "bg-primary/15 text-primary" : "hover:bg-accent"
                    )}
                  >
                    <span className="w-16 shrink-0 font-mono tabular-nums text-muted-foreground">
                      {p.pid}
                    </span>
                    <span className="w-52 shrink-0 truncate font-medium">{p.name}</span>
                    <span className="flex-1 truncate text-muted-foreground" title={p.path}>
                      {p.path || "—"}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t pt-3 -mx-4 px-4">
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
