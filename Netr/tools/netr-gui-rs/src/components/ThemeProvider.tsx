import { useEffect } from "react";
import { useTheme } from "@/store/themeStore";

/**
 * 监听 theme store,把对应 class 写到 <html>。
 * 系统主题模式会跟随 prefers-color-scheme。
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = useTheme((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove("light", "dark");

    if (theme === "system") {
      const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.classList.add(systemDark ? "dark" : "light");
    } else {
      root.classList.add(theme);
    }
  }, [theme]);

  return <>{children}</>;
}
