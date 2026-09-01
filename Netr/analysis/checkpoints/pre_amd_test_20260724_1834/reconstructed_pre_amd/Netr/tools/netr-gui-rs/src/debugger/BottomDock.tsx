import { Search, ListChecks, ScrollText, ChevronsDown, Crosshair, FileCode2, Boxes, Target, Compass, Workflow, TextSelect, FileSearch, Binary } from "lucide-react";

import { ScannerPanel } from "./ScannerPanel";
import { WatchTable } from "./WatchTable";
import { DbgEvtConsole } from "./DbgEvtConsole";
import { PtrScanPanel } from "./PtrScanPanel";
import { ScriptPanel } from "./ScriptPanel";
import { ModulesPanel } from "./ModulesPanel";
import { AobPanel } from "./AobPanel";
import { GlobalsPanel } from "./GlobalsPanel";
import { FunctionsPanel } from "./FunctionsPanel";
import { StringsPanel } from "./StringsPanel";
import { SignaturesPanel } from "./SignaturesPanel";
import { HexPanel } from "./HexPanel";
import { useSession, type BottomTab } from "./sessionStore";
import { cn } from "@/lib/utils";

/**
 * 底部停靠区 — Scanner / Watches / Log 三个 tab 切换。
 * 可折叠(顶角 ▼ 按钮)。
 */
export function BottomDock() {
  const { bottomTab, setBottomTab, setBottomCollapsed, pid } = useSession();
  if (!pid) return null;

  const TABS: { v: BottomTab; label: string; Icon: typeof Search }[] = [
    { v: "scanner", label: "扫描", Icon: Search },
    { v: "watches", label: "监视", Icon: ListChecks },
    { v: "hex", label: "Hex", Icon: Binary },
    { v: "aob", label: "AOB", Icon: Target },
    { v: "globals", label: "候选全局", Icon: Compass },
    { v: "functions", label: "函数", Icon: Workflow },
    { v: "strings", label: "字符串", Icon: TextSelect },
    { v: "signatures", label: "签名", Icon: FileSearch },
    { v: "ptrscan", label: "指针扫描", Icon: Crosshair },
    { v: "modules", label: "模块", Icon: Boxes },
    { v: "script", label: "脚本", Icon: FileCode2 },
    { v: "log", label: "日志", Icon: ScrollText },
  ];

  return (
    <div className="flex h-full flex-col border-t border-border bg-card/30">
      <div className="flex h-8 shrink-0 items-center gap-px border-b border-border bg-card/60 pl-1 text-xs">
        {TABS.map(({ v, label, Icon }) => (
          <button
            key={v}
            type="button"
            onClick={() => setBottomTab(v)}
            className={cn(
              "flex h-7 items-center gap-1.5 rounded-md px-3 text-[11px] font-medium transition-colors",
              bottomTab === v
                ? "bg-primary/15 text-primary"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
            )}
          >
            <Icon className="h-3 w-3" />
            {label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setBottomCollapsed(true)}
          title="折叠"
          className="ml-auto mr-1 flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <ChevronsDown className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-hidden">
        {bottomTab === "scanner" && <ScannerPanel pid={pid} />}
        {bottomTab === "watches" && <WatchTable />}
        {bottomTab === "hex" && <BottomHexPanel />}
        {bottomTab === "aob" && <AobPanel />}
        {bottomTab === "globals" && <GlobalsPanel />}
        {bottomTab === "functions" && <FunctionsPanel />}
        {bottomTab === "strings" && <StringsPanel />}
        {bottomTab === "signatures" && <SignaturesPanel />}
        {bottomTab === "ptrscan" && <PtrScanPanel />}
        {bottomTab === "modules" && <ModulesPanel />}
        {bottomTab === "script" && <ScriptPanel />}
        {bottomTab === "log" && <DbgEvtConsole />}
      </div>
    </div>
  );
}

function BottomHexPanel() {
  const { bottomHexAddress, setBottomHexAddress } = useSession();
  return (
    <HexPanel
      address={bottomHexAddress}
      onAddressChange={setBottomHexAddress}
      showGoto
      title="Hex"
    />
  );
}
