import { Outlet } from "react-router-dom";
import { TitleBar } from "./TitleBar";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import { StatusBar } from "./StatusBar";
import { ErrorBoundary } from "@/components/common/ErrorBoundary";
import { ElevationBanner } from "@/components/common/ElevationBanner";

/**
 * 主壳:
 *   ┌─────── TitleBar ────────┐
 *   ├────────┬────────────────┤
 *   │Sidebar │ Header         │
 *   │        ├────────────────┤
 *   │        │ <Outlet/>      │
 *   │        │ (page content) │
 *   ├────────┴────────────────┤
 *   │ StatusBar               │
 *   └─────────────────────────┘
 */
export function Shell() {
  return (
    <div className="flex h-full min-h-0 flex-col bg-background text-foreground">
      <TitleBar />
      <ElevationBanner />
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <Header />
          <main className="min-h-0 flex-1 overflow-y-auto">
            <div className="mx-auto max-w-7xl p-6 lg:p-8">
              <ErrorBoundary>
                <Outlet />
              </ErrorBoundary>
            </div>
          </main>
        </div>
      </div>
      <StatusBar />
    </div>
  );
}
