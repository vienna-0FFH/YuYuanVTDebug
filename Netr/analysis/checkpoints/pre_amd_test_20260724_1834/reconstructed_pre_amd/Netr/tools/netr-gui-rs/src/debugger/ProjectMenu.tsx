import { useEffect, useRef, useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { FileText, FolderOpen, Save, FilePlus, ChevronDown, Clock, Play, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { dbgIpc, type ProjectDoc, type RecentProject, errMsg } from "./ipc";
import { useSession, type WatchItem, type Bookmark } from "./sessionStore";
import { systemIpc, type ProcessInfo } from "@/ipc";
import { cn } from "@/lib/utils";
import { clearExprModuleCache } from "./expr";

/**
 * 项目菜单 — 类似 CE File: 新建 / 打开 / 保存 / 另存为 / 最近.
 * 保存内容: 监视列表 + 书签 + 备注 + 当前光标地址 + 目标 exe 名.
 * 加载后按 exe 名找进程 attach.
 */
export function ProjectMenu({ showQuickLaunch = false }: { showQuickLaunch?: boolean }) {
  const s = useSession();
  const [open, setOpen] = useState(false);
  const [recent, setRecent] = useState<RecentProject[]>([]);
  const [launching, setLaunching] = useState(false);
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
          s.setAttachingPid(found.pid);
          try {
            const result = await dbgIpc.attach(found.pid, s.debugMode);
            s.attach(found.pid, found.name, result);
            toast.success(
              `已加载项目并附加到 ${found.name} (PID ${found.pid}) · ${result.mode === "vt" ? "VT" : "Native"}`
            );
          } finally {
            useSession.getState().setAttachingPid(null);
          }
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

  async function detachForProjectChange(mode: "native" | "vt"): Promise<boolean> {
    const current = useSession.getState();
    if (current.attachingPid) {
      toast.warning(`正在附加 PID ${current.attachingPid}，请稍后再新建项目`);
      return false;
    }
    if (!current.pid) return true;
    if (!confirm(`当前已附加 ${current.processName} (PID ${current.pid})。新建项目将先安全解附，继续?`)) {
      return false;
    }
    const pid = current.pid;
    try {
      for (const watch of current.watches) {
        if (watch.frozen) {
          try { await dbgIpc.freezeClear(pid, Number(watch.address)); } catch {/* detach 会继续兜底清理 */}
        }
      }
      await dbgIpc.detach(pid);
      useSession.getState().detach();
      useSession.getState().setDebugMode(mode);
      clearExprModuleCache();
      return true;
    } catch (e) {
      toast.error(`新建项目前解附失败: ${errMsg(e)}`);
      return false;
    }
  }

  function applyFreshProject(targetExeName: string | null, dirty: boolean) {
    const current = useSession.getState();
    current.loadProject({
      watches: [], bookmarks: [], notes: "",
      targetExeName,
      address: 0n,
      path: "",
    });
    current.setProjectPath(null);
    current.setFollow(null);
    current.setAnnotations({ labels: {}, comments: {}, functions: {} });
    current.setProjectDirty(dirty);
  }

  async function initializeAttachedTarget(pid: number, exeName: string) {
    clearExprModuleCache();
    try {
      const modules = await dbgIpc.listModules(pid);
      const main = modules.find((m) => m.name.toLowerCase() === exeName.toLowerCase()) ?? modules[0];
      if (main) useSession.getState().setAddress(BigInt(main.base));
    } catch {/* attach 已成功，模块枚举失败不撤销会话 */}
    try {
      const threads = await dbgIpc.listThreads(pid);
      if (threads.length > 0) useSession.getState().setSelectedTid(threads[0].tid);
    } catch {/* attach 已成功，线程枚举失败不撤销会话 */}
  }

  async function newExecutableProject() {
    const picked = await openDialog({
      multiple: false,
      directory: false,
      title: "选择要启动并调试的 EXE",
      filters: [{ name: "Windows 可执行文件", extensions: ["exe"] }],
    });
    const exePath = Array.isArray(picked) ? picked[0] : picked;
    if (!exePath) return;

    const before = useSession.getState();
    if (before.projectDirty && !confirm("当前项目未保存。放弃改动并打开新的 EXE?")) return;
    const requestedMode = before.debugMode;
    const exeName = exePath.split(/[\\/]/).pop() || exePath;

    setLaunching(true);
    setOpen(false);
    let launchedPid: number | null = null;
    try {
      if (!(await detachForProjectChange(requestedMode))) return;

      await dbgIpc.projectNew();
      applyFreshProject(exeName, true);

      const launch = await dbgIpc.launchExecutable(exePath, requestedMode);
      launchedPid = launch.attach.pid;
      useSession.getState().setAttachingPid(launchedPid);
      useSession.getState().attach(launchedPid, exeName, launch.attach);
      await initializeAttachedTarget(launchedPid, exeName);
      useSession.getState().setAddress(BigInt(launch.entry_address));
      useSession.getState().setSelectedTid(launch.primary_tid);

      // The process remains gated until the session PID above is visible to
      // the hit listener; this prevents a fast entry hit from being dropped.
      const stopped = await dbgIpc.runToEntry(launchedPid);
      useSession.getState().setAddress(BigInt(stopped.entry_address));
      useSession.getState().setSelectedTid(stopped.primary_tid);

      toast.success(`已启动 ${exeName} (PID ${launchedPid}) · ${launch.attach.mode === "vt" ? "VT" : "Native"}`, {
        description: stopped.stopped_at_entry
          ? `已停在程序入口 0x${stopped.entry_address.toString(16).toUpperCase()}`
          : `入口一次性断点已布置，正在运行到 0x${stopped.entry_address.toString(16).toUpperCase()}`,
      });
    } catch (e) {
      if (launchedPid !== null) {
        try {
          await dbgIpc.detach(launchedPid);
          useSession.getState().detach();
          useSession.getState().setDebugMode(requestedMode);
          toast.error(`启动并停在入口失败 (PID ${launchedPid}): ${errMsg(e)}`, {
            description: "挂起启动、入口断点和调试会话已安全回滚。",
            duration: 10000,
          });
        } catch (rollbackError) {
          // The backend still owns this PID when authoritative cleanup fails.
          // Keep the visible session so the user can retry Detach; clearing it
          // here would strand a DebugObject event, a suspended VT thread, or an
          // entry INT3 with no remaining recovery path.
          toast.error(`启动失败且安全回滚未完成 (PID ${launchedPid})`, {
            description: `${errMsg(e)}；回滚错误: ${errMsg(rollbackError)}。会话已保留，请重试“解附”。`,
            duration: 15000,
          });
        }
      } else {
        toast.error(`新建 EXE 项目失败: ${errMsg(e)}`);
      }
    } finally {
      useSession.getState().setAttachingPid(null);
      setLaunching(false);
    }
  }

  async function newBlankProject() {
    if (s.projectDirty && !confirm("当前项目未保存. 放弃改动新建?")) return;
    try {
      const requestedMode = useSession.getState().debugMode;
      if (!(await detachForProjectChange(requestedMode))) return;
      await dbgIpc.projectNew();
      applyFreshProject(null, false);
      setOpen(false);
      toast.success("已新建空白项目");
    } catch (e) {
      toast.error(`新建失败: ${errMsg(e)}`);
    }
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
    <div ref={wrap} className="relative flex items-center gap-1">
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
      {showQuickLaunch && (
        <button
          type="button"
          onClick={() => void newExecutableProject()}
          disabled={launching}
          className={cn(
            "flex h-7 items-center gap-1.5 rounded-md border border-border px-2 text-xs transition-colors",
            "bg-primary/10 text-primary hover:bg-primary/20 disabled:cursor-wait disabled:opacity-60"
          )}
          title="选择一个 EXE，启动进程并按当前 Native/VT 模式建立内置调试会话"
        >
          {launching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
          打开 EXE
        </button>
      )}
      {open && (
        <div className="absolute left-0 top-8 z-50 w-64 rounded-md border bg-popover text-popover-foreground shadow-xl">
          <MenuItem icon={Play} label="新建项目并打开 EXE..." onClick={() => void newExecutableProject()} disabled={launching} />
          <MenuItem icon={FilePlus} label="新建空白项目" onClick={() => void newBlankProject()} disabled={launching} />
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
