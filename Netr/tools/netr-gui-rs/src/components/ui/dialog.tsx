import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  /** 最大宽度 tailwind class,默认 max-w-2xl */
  widthClass?: string;
  /** 关闭按钮可见性,默认 true */
  showClose?: boolean;
  /** 点击外部关闭,默认 true */
  closeOnOverlay?: boolean;
}

/**
 * 轻量 Dialog — 不引第三方,Portal 到 body,Esc 关闭,锁滚动。
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  widthClass = "max-w-2xl",
  showClose = true,
  closeOnOverlay = true,
}: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      onMouseDown={(e) => {
        if (!closeOnOverlay) return;
        if (panelRef.current && !panelRef.current.contains(e.target as Node)) onClose();
      }}
    >
      {/* 蒙层 */}
      <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" aria-hidden />

      {/* 面板 */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        className={cn(
          "relative z-10 flex max-h-[85vh] w-full flex-col rounded-xl border bg-card text-card-foreground shadow-2xl shadow-primary/10",
          "animate-in fade-in-0 zoom-in-95 duration-150",
          widthClass
        )}
      >
        {(title || showClose) && (
          <div className="flex items-start justify-between gap-4 border-b px-5 py-4">
            <div className="min-w-0 flex-1">
              {title && (
                <h2 className="text-base font-semibold leading-tight tracking-tight">{title}</h2>
              )}
              {description && (
                <p className="mt-1 text-sm text-muted-foreground">{description}</p>
              )}
            </div>
            {showClose && (
              <button
                type="button"
                onClick={onClose}
                aria-label="关闭"
                className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        )}

        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </div>,
    document.body
  );
}
