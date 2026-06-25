import { useAuth } from "@/store/authStore";
import { useDriver, serviceStateLabel, serviceStateTone } from "@/store/driverStore";
import { cn } from "@/lib/utils";

type Tone = "success" | "warning" | "destructive" | "muted" | "info" | "primary";

export function StatusBar() {
  const user = useAuth((s) => s.user);
  const driverLicensed = useAuth((s) => s.driverLicensed);
  const service = useDriver((s) => s.service);
  const deviceOpen = useDriver((s) => s.deviceOpen);
  const status = useDriver((s) => s.status);
  const selfProtected = useDriver((s) => s.selfProtected);

  return (
    <footer className="flex h-7 items-center gap-2 border-t border-border bg-card/40 px-3 text-xs backdrop-blur-sm">
      <PillItem label="Service" value={serviceStateLabel(service?.state)} tone={serviceStateTone(service?.state)} pulse={service?.state === "running"} />
      <PillItem label="Device" value={deviceOpen ? "Open" : "Closed"} tone={deviceOpen ? "success" : "muted"} />
      {status && (
        <PillItem label="HV" value={status.hypervisor_active ? "ON" : "OFF"} tone={status.hypervisor_active ? "success" : "muted"} />
      )}
      <PillItem label="Self" value={selfProtected ? "已保护" : "未保护"} tone={selfProtected ? "success" : "muted"} />


      <div className="flex-1" />

      {user ? (
        <>
          <PillItem
            label="License"
            value={`${user.subject_type === "account" ? "账号" : "卡密"} #${user.subject_id}`}
            tone="info"
          />
          <PillItem
            label="Driver"
            value={driverLicensed ? "已激活" : "待下发"}
            tone={driverLicensed ? "success" : "warning"}
          />
        </>
      ) : (
        <PillItem label="License" value="未登录" tone="warning" />
      )}
    </footer>
  );
}

function PillItem({
  label,
  value,
  tone,
  pulse,
}: {
  label: string;
  value: string;
  tone: Tone;
  pulse?: boolean;
}) {
  const dotBg = {
    success: "bg-success",
    warning: "bg-warning",
    destructive: "bg-destructive",
    muted: "bg-muted-foreground",
    info: "bg-info",
    primary: "bg-primary",
  }[tone];

  return (
    <div className="flex items-center gap-1.5">
      <span className={cn("h-1.5 w-1.5 rounded-full", dotBg, pulse && "pill-dot-pulse")} />
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium text-foreground/90">{value}</span>
    </div>
  );
}
