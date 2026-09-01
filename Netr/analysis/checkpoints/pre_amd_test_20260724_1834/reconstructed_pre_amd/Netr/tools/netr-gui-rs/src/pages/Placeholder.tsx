import { Construction } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

/**
 * Phase 0 占位:其它 page 还未实现,统一显示这个壳子。
 * 后续 phase 各 page 替换为真实内容。
 */
export function Placeholder({
  title,
  description,
  phase,
}: {
  title: string;
  description: string;
  phase: string;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{description}</p>
      </div>

      <Card>
        <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
          <Construction className="h-10 w-10 text-muted-foreground" />
          <div className="text-sm font-medium">本页计划在 {phase} 实现</div>
          <div className="max-w-md text-xs text-muted-foreground">
            Phase 0 仅完成脚手架与布局,业务页面将按计划逐个迁移。
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
