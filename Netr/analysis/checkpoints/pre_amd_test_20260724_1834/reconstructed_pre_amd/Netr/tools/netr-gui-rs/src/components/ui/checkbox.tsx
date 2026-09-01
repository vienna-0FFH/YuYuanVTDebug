import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * 简易 checkbox(不依赖 @radix-ui/react-checkbox 以减一个包)。
 * 受控:value + onChange。
 */
interface CheckboxProps {
  id?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  className?: string;
  disabled?: boolean;
}

export function Checkbox({ id, checked, onCheckedChange, className, disabled }: CheckboxProps) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      id={id}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "peer h-4 w-4 shrink-0 rounded-sm border border-primary shadow",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
        "disabled:cursor-not-allowed disabled:opacity-50",
        checked && "bg-primary text-primary-foreground",
        className
      )}
    >
      {checked && <Check className="h-3 w-3" />}
    </button>
  );
}
