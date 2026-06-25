import { Minus, Square, X, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { cn } from "@/lib/utils";

/**
 * 自定义无边框窗口标题栏。
 * - 左侧 app icon + 标题
 * - 中间区域可拖拽(data-tauri-drag-region)
 * - 右侧三件套:最小化 / 还原-最大化 / 关闭
 *
 * Tauri v2 用 getCurrentWindow() 拿当前 webview window。
 */
export function TitleBar() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const win = getCurrentWindow();
    win.isMaximized().then(setMaximized);
    const unlisten = win.onResized(() => {
      win.isMaximized().then(setMaximized);
    });
    return () => {
      unlisten.then((f) => f());
    };
  }, []);

  const win = getCurrentWindow();

  return (
    <div
      data-tauri-drag-region
      className="flex h-9 select-none items-center border-b border-border bg-card/60 backdrop-blur-sm"
    >
      <div data-tauri-drag-region className="flex flex-1 items-center gap-2 px-3">
        <div className="bg-steel h-4 w-4 rounded-sm shadow-sm shadow-primary/40" />
        <span data-tauri-drag-region className="text-xs font-semibold tracking-wide text-foreground/90">
          御元虚拟化安全工具
        </span>
      </div>

      <div className="flex h-full">
        <TitleBarButton onClick={() => win.minimize()} aria-label="最小化">
          <Minus className="h-3.5 w-3.5" />
        </TitleBarButton>
        <TitleBarButton onClick={() => win.toggleMaximize()} aria-label="最大化">
          {maximized ? <Copy className="h-3 w-3" /> : <Square className="h-3 w-3" />}
        </TitleBarButton>
        <TitleBarButton
          onClick={() => win.close()}
          aria-label="关闭"
          className="hover:bg-destructive hover:text-destructive-foreground"
        >
          <X className="h-3.5 w-3.5" />
        </TitleBarButton>
      </div>
    </div>
  );
}

function TitleBarButton({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      className={cn(
        "flex h-full w-11 items-center justify-center text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground",
        className
      )}
      {...props}
    />
  );
}
