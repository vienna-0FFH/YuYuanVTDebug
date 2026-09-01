import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * shadcn 风格的 className 合并工具。
 * - clsx 处理条件式 class
 * - twMerge 解决 tailwind 冲突(后面的覆盖前面的)
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
