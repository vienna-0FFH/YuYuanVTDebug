"""Phase G ring buffer 调试探针 —— 直接调 IOCTL_HV_GET_DBGEVT 跳过 GUI 轮询。

用法: 在装好驱动 + GUI 已启动并保护 CE 后,从 cmd/PowerShell 跑:
    python C:\\Users\\Administrator\\source\\repos\\MyDriver1\\Netr\\tools\\netr-gui\\probe_dbgevt.py

预期输出:
    NextSeq = N (N > 0 表示驱动 ring 被填过事件)
    Events: K 条
        [INFO] [AddDebugger] caller=12345 ... DebuggerProxy enabled
        ...

如果 NextSeq = 0 → 驱动里 HvDbgEvtPost 从未被调用 → Phase G 在驱动那侧没生效
                  (说明你装的驱动不是 Phase G 之后的版本)
如果 NextSeq > 0 但 Events = 0 → since_sequence 被推进过头(GUI 启动时拉过一次)
                                   传 since=0 重新拉应该看到全部
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from netr.ioctl import NetrDevice
from netr.client import NetrClient


def main():
    with NetrClient() as c:
        # since=0 拉所有存活事件
        events, next_seq = c.dbgevt_pull(since_sequence=0, max_count=256)
        print(f"NextSeq = {next_seq}")
        print(f"Events: {len(events)} 条")
        for ev in events:
            sev = ev.severity_name
            cat = ev.category_name
            detail = ev.detail_str
            status = f" status=0x{ev.Status & 0xFFFFFFFF:08X}" if ev.Status else ""
            ct = []
            if ev.CallerPid: ct.append(f"caller={ev.CallerPid}")
            if ev.TargetPid: ct.append(f"target={ev.TargetPid}")
            ctstr = (" " + " ".join(ct)) if ct else ""
            print(f"  [{sev:5s}] [{cat}]{ctstr}{status}  {detail}")


if __name__ == "__main__":
    main()
