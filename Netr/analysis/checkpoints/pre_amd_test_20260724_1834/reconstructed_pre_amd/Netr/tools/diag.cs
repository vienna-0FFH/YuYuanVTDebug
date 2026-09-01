// 编译: csc diag.cs
// 用法: diag.exe                  → 每 10ms 持续读, 输出到控制台 + diag.log (默认)
//       diag.exe 200              → 每 200ms 读一次
//       diag.exe once             → 只读一次后退出 (不写文件)
// 日志文件: diag.exe 同目录下的 diag.log, 追加模式
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

class Diag
{
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3;
    const uint IOCTL_HV_GET_DIAG_SNAPSHOT = 0x2222C0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    struct DiagSnapshot
    {
        public ulong HostNmiCount;
        public ulong HostMceCount;
        public ulong HostDfCount;
        public ulong HostGpCount;
        public ulong NmiCallbackCount;
        public ulong VmExitCounter;
        public ulong IstStack0;       // CPU0 IST1 (NMI)
        public ulong IstStack1;       // CPU0 IST2 (#MC)
        public ulong IstStack2;       // CPU0 IST3 (#DF)
        public ulong IstStackSize;
        public uint  HostTssInitMask;
        public uint  VcpuVirtualizedMask;
        public uint  ActiveCpuCount;
        public uint  BuildFlags;
    }

    static string FindDeviceName()
    {
        // 从注册表读 Netr 动态设备名
        try {
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\NetrSvc")) {
                if (key != null) {
                    var name = key.GetValue("DeviceName") as string;
                    if (!string.IsNullOrEmpty(name)) return @"\\.\" + name;
                }
            }
        } catch {}
        return null;
    }

    static StreamWriter g_LogWriter;

    static void Out(string s)
    {
        Console.WriteLine(s);
        if (g_LogWriter != null) {
            try {
                g_LogWriter.WriteLine(s);
                g_LogWriter.Flush();
            } catch {}
        }
    }

    static int Read(SafeFileHandle h)
    {
        int size = Marshal.SizeOf(typeof(DiagSnapshot));
        IntPtr buf = Marshal.AllocHGlobal(size);
        try {
            uint ret;
            if (!DeviceIoControl(h, IOCTL_HV_GET_DIAG_SNAPSHOT, IntPtr.Zero, 0, buf, (uint)size, out ret, IntPtr.Zero)) {
                Out("DeviceIoControl failed: " + Marshal.GetLastWin32Error());
                return -1;
            }
            DiagSnapshot s = (DiagSnapshot)Marshal.PtrToStructure(buf, typeof(DiagSnapshot));
            string flags = "";
            if ((s.BuildFlags & 0x01) != 0) flags += "TSS ";
            if ((s.BuildFlags & 0x02) != 0) flags += "IDT ";
            if ((s.BuildFlags & 0x04) != 0) flags += "SYSCR3 ";
            if ((s.BuildFlags & 0x08) != 0) flags += "CET ";
            if ((s.BuildFlags & 0x10) != 0) flags += "GUARD ";
            if ((s.BuildFlags & 0x20) != 0) flags += "MINIMAL ";
            Out(string.Format(
                "[{0:HH:mm:ss.fff}] NMI={1} MCE={2} #DF={3} #GP={4} NmiCb={5} VmExit={6} TssMask=0x{7:X} VcpuMask=0x{8:X} CPU={9} Flags=[{10}]",
                DateTime.Now, s.HostNmiCount, s.HostMceCount, s.HostDfCount, s.HostGpCount, s.NmiCallbackCount,
                s.VmExitCounter, s.HostTssInitMask, s.VcpuVirtualizedMask, s.ActiveCpuCount, flags.Trim()));
            Out(string.Format(
                "                IST (CPU0): NMI=0x{0:X16} MCE=0x{1:X16} DF=0x{2:X16} size=0x{3:X}",
                s.IstStack0, s.IstStack1, s.IstStack2, s.IstStackSize));
            return 0;
        } finally {
            Marshal.FreeHGlobal(buf);
        }
    }

    static int Main(string[] args)
    {
        string devName = FindDeviceName();
        if (devName == null) {
            Console.WriteLine("ERROR: cannot find device name in HKLM\\Software\\NetrSvc\\DeviceName");
            Console.WriteLine("(driver not loaded, or registry not published)");
            return 1;
        }

        bool once = args.Length > 0 && args[0] == "once";
        int intervalMs = 10;
        if (args.Length > 0 && !once) {
            int parsed;
            if (int.TryParse(args[0], out parsed) && parsed > 0) intervalMs = parsed;
        }

        // 只在 loop 模式打开日志文件 (once 模式不写文件)
        if (!once) {
            try {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string logPath = Path.Combine(Path.GetDirectoryName(exePath), "diag.log");
                g_LogWriter = new StreamWriter(logPath, append: true);
                g_LogWriter.WriteLine("===== diag.exe started at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " (interval " + intervalMs + "ms) =====");
                g_LogWriter.Flush();
                Console.WriteLine("Logging to: " + logPath);
            } catch (Exception e) {
                Console.WriteLine("WARN: cannot open diag.log: " + e.Message + " (console only)");
            }
        }

        Out("Device: " + devName);

        using (var h = CreateFileW(devName, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero)) {
            if (h.IsInvalid) {
                Out("CreateFile failed: " + Marshal.GetLastWin32Error());
                if (g_LogWriter != null) g_LogWriter.Close();
                return 1;
            }

            if (once) return Read(h);

            Out("Looping every " + intervalMs + "ms. Ctrl+C to stop.");
            while (true) {
                Read(h);
                Thread.Sleep(intervalMs);
            }
        }
    }
}
