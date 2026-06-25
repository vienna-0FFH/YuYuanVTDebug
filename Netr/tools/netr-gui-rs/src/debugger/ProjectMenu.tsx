import { useEffect, useRef, useState } from "react";
import { FileText, FolderOpen, Save, FilePlus, ChevronDown, Clock } from "lucide-react";
import { toast } from "sonner";

import { dbgIpc, type ProjectDoc, type RecentProject, errMsg } from "./ipc";
import { useSession, type WatchItem, type Bookmark } from "./sessionStore";
import { systemIpc, type ProcessInfo } from "@/ipc";
import { cn } from "@/lib/utils";

/**
 * 项目菜单 — 类似 CE File: 新建 / 打开 / 保存 / 另存为 / 最近.
 * 保存内容: 监视列表 + 书签 + 备注 + 当前光标地址 + 目标 exe 名.
 * 加载后按 exe 名找进程 attach.
 */
export function ProjectMenu() {
  const s = useSession();
  const [open, setOpen] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>([]);
  const wrap = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    dbgIpc.projectListRecent().then(setRecent).catch(() => setRecent([]));
  }, [open]);
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", handler);
    return () => window.removeEventListener("mousedown", handler);
  }, []);
  // 监听 Ctrl+S 全局事件
  useEffect(() => {
    const h = () => { void save(); };
    window.addEventListener("gm:project-save", h);
    return () => window.removeEventListener("gm:project-save", h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.projectPath, s.projectDirty, s.watches, s.bookmarks, s.notes, s.address, s.targetExeName]);

  function buildDoc(): ProjectDoc {
    return {
      version: 1,
      target: {
        exe_name: s.targetExeName ?? s.processName ?? "",
        module_name: null,
        last_pid: s.pid,
      },
      watches: s.watches.map<ProjectDoc["watches"][number]>((w: WatchItem) => ({
        address: w.address.toString(16),
        type_: w.type,
        description: w.description,
        frozen: w.frozen,
        frozen_bytes: w.frozenBytes ?? null,
      })),
      bookmarks: s.bookmarks.map<ProjectDoc["bookmarks"][number]>((b: Bookmark) => ({
        address: b.address.toString(16),
        label: b.label,
        note: b.note,
      })),
      notes: s.notes,
      main_address: s.address.toString(16),
      created_at: null,
      modified_at: null,
    };
  }

  async function applyDoc(doc: ProjectDoc, path: string) {
    const watches: WatchItem[] = doc.watches.map((w, i) => ({
      id: `loaded-w-${i}-${Date.now()}`,
      address: BigInt("0x" + w.address),
      type: w.type_ as WatchItem["type"],
      description: w.description,
      display: "?",
      frozen: w.frozen,
      frozenBytes: w.frozen_bytes ?? undefined,
    }));
    const bookmarks: Bookmark[] = doc.bookmarks.map((b, i) => ({
      id: `loaded-bm-${i}-${Date.now()}`,
      address: BigInt("0x" + b.address),
      label: b.label,
      note: b.note,
    }));
    const address = doc.main_address ? BigInt("0x" + doc.main_address) : 0n;
    s.loadProject({
      watches, bookmarks, notes: doc.notes, address,
      targetExeName: doc.target?.exe_name ?? null,
      path,
    });
    // 注解后端已被 project_load 替换, 这里拉快照刷反汇编显示
    void s.refreshAnnotations();
    // 自动 attach
    if (doc.target?.exe_name && !s.pid) {
      try {
        const procs: ProcessInfo[] = await systemIpc.listProcesses();
        const found = procs.find((p) => p.name.toLowerCase() === doc.target!.exe_name.toLowerCase());
        if (found) {
          s.attach(found.pid, found.name);
          toast.success(`已加载项目并附加到 ${found.name} (PID ${found.pid})`);
          return;
        }
        toast.info(`项目已加载. 目标进程 ${doc.target.exe_name} 不在运行 — 启动后再附加`);
      } catch {
        toast.info("项目已加载,自动附加失败 — 手动选进程");
      }
    } else {
      toast.success("项目已加载");
    }
  }

  async function newProject() {
    if (s.projectDirty && !confirm("当前项目未保存. 放弃改动新建?")) return;
    s.loadProject({
      watches: [], bookmarks: [], notes: "",
      targetExeName: s.processName ?? null,
      address: 0n,
      path: "",
    });
    s.setProjectPath(null);
    setOpen(false);
  }

  async function openProject() {
    try {
      const p = await dbgIpc.projectPickOpen();
      if (!p) return;
      const doc = await dbgIpc.projectLoad(p);
      await applyDoc(doc, p);
      setOpen(false);
    } catch (e) {
      toast.error(`打开失败: ${errMsg(e)}`);
    }
  }

  async function openRecent(p: string) {
    try {
      const doc = await dbgIpc.projectLoad(p);
      await applyDoc(doc, p);
      setOpen(false);
    } catch (e) {
      toast.error(`打开失败: ${errMsg(e)}`);
    }
  }

  async function save() {
    let path = s.projectPath;
    if (!path) {
      const picked = await dbgIpc.projectPickSave(s.targetExeName ? `${s.targetExeName}.gmproj` : undefined);
      if (!picked) return;
      path = picked;
    }
    try {
      await dbgIpc.projectSave(path, buildDoc());
      s.setProjectPath(path);
      toast.success(`已保存 ${path}`);
      setOpen(false);
    } catch (e) {
      toast.error(`保存失败: ${errMsg(e)}`);
    }
  }

  async function saveAs() {
    const picked = await dbgIpc.projectPickSave(s.projectPath ? undefined : (s.targetExeName ? `${s.targetExeName}.gmproj` : "未命名.gmproj"));
    if (!picked) return;
    try {
      await dbgIpc.projectSave(picked, buildDoc());
      s.setProjectPath(picked);
      toast.success(`已另存为 ${picked}`);
      setOpen(false);
    } catch (e) {
      toast.error(`保存失败: ${errMsg(e)}`);
    }
  }

  const projectName = s.projectPath
    ? s.projectPath.split(/[\\/]/).pop()?.replace(/\.gmproj$/, "")
    : null;

  return (
    <div ref={wrap} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "flex h-7 items-center gap-1.5 rounded-md px-2 text-xs transition-colors",
          "text-muted-foreground hover:bg-accent hover:text-foreground"
        )}
        title="项目"
      >
        <FileText className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">
          {projectName ?? "未命名"}
          {s.projectDirty && <span className="ml-1 text-amber-400">*</span>}
        </span>
        <ChevronDown className="h-3 w-3 opacity-60" />
      </button>
      {open && (
        <div className="absolute left-0 top-8 z-50 w-64 rounded-md border bg-popover text-popover-foreground shadow-xl">
          <MenuItem icon={FilePlus} label="新建项目" onClick={() => void newProject()} />
          <MenuItem icon={FolderOpen} label="打开..." onClick={() => void openProject()} />
          <MenuSep />
          <MenuItem icon={Save} label={s.projectPath ? "保存" : "保存..."} onClick={() => void save()} disabled={!s.projectDirty && !!s.projectPath} />
          <MenuItem icon={Save} label="另存为..." onClick={() => void saveAs()} />
          {recent.length > 0 && (
            <>
              <MenuSep />
              <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-muted-foreground">最近</div>
              {recent.map((r) => (
                <button
                  key={r.path}
                  type="button"
                  onClick={() => void openRecent(r.path)}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-accent"
                  title={r.path}
                >
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="flex-1 truncate">{r.name}</span>
                  <span className="text-[10px] text-muted-foreground">
                    {new Date(r.modified * 1000).toLocaleDateString()}
                  </span>
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function MenuItem({
  icon: Icon, label, onClick, disabled,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      {label}
    </button>
  );
}
function MenuSep() {
  return <div className="my-1 border-t border-border/40" />;
}
