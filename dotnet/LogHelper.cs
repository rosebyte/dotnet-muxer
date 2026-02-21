using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DotnetMuxer;

internal sealed class LogHelper
{
    internal const string Unknown = "unknown";

    public static void Run(string testHostPath, string[] args)
    {
        var verbose = Environment.GetEnvironmentVariable("DOTNET_MUXER_VERBOSE");
        if (!string.Equals(verbose, "true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        
        var sb = new StringBuilder(string.Join(" ", args));
        Write(sb, "target", testHostPath);
        Write(sb, "cwd", Environment.CurrentDirectory);
        Write(sb, "process", $"({Environment.ProcessId}) {Environment.ProcessPath}");
        AddParents(sb, Environment.ProcessId);
        Write(sb, "ts", DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        sb.AppendLine();

        var processPath = Environment.ProcessPath;
        var dir = processPath is null ? null : Path.GetDirectoryName(processPath);
        var logPath = Path.Combine(string.IsNullOrWhiteSpace(dir) ? "." : dir, "log.log");
        File.AppendAllText(logPath, sb.ToString());
    }

    private static void Write(StringBuilder sb, string key, string value)
    {
        sb.AppendLine("  ");
        sb.Append(key);
        sb.Append("=\"");
        sb.Append(value);
        sb.Append("\" ");
    }

    private static void AddParents(StringBuilder sb, int pid)
    {
        var visited = new HashSet<int>();

        while (pid != 0)
        {
            if (!visited.Add(pid))
            {
                break;
            }

            var (parentName, parentId) = GetParentProcess(pid);
            Write(sb, "parent", $"({parentId}) {parentName}");
            pid = parentId;
        }
    }

    private static (string Name, int ParentPid) GetParentProcess(int pid)
    {
        if (OperatingSystem.IsWindows())
        {
            return ParentProcessNameWindows(pid);
        }

        if (OperatingSystem.IsLinux())
        {
            return ParentProcessNameLinux(pid);
        }

        if (OperatingSystem.IsMacOS())
        {
            return ParentProcessNameMac(pid);
        }

        return (Unknown, 0);
    }

    private static (string Name, int ParentPid) ParentProcessNameLinux(int pid)
    {
        try
        {
            var statusPath = $"/proc/{pid}/status";
            if (!File.Exists(statusPath))
            {
                return (Unknown, 0);
            }

            var ppid = 0;
            foreach (var line in File.ReadLines(statusPath))
            {
                if (!line.StartsWith("PPid:", StringComparison.Ordinal))
                {
                    continue;
                }

                var raw = line.Substring("PPid:".Length).Trim();
                if (!int.TryParse(raw, out ppid) || ppid <= 0 || ppid == pid)
                {
                    return (Unknown, 0);
                }

                break;
            }

            if (ppid <= 0)
            {
                return (Unknown, 0);
            }

            var commPath = $"/proc/{ppid}/comm";
            var parentName = File.Exists(commPath) ? File.ReadAllText(commPath).Trim() : Unknown;
            return (string.IsNullOrWhiteSpace(parentName) ? Unknown : parentName, ppid);
        }
        catch
        {
            return (Unknown, 0);
        }
    }

    private static (string Name, int ParentPid) ParentProcessNameMac(int pid)
    {
        try
        {
            var ppid = GetParentPidMac(pid);
            if (ppid <= 0 || ppid == pid)
            {
                return (Unknown, 0);
            }

            var parentName = GetProcessNameMac(ppid);
            return (string.IsNullOrWhiteSpace(parentName) ? Unknown : parentName, ppid);
        }
        catch
        {
            return (Unknown, 0);
        }
    }

    private static (string Name, int ParentPid) ParentProcessNameWindows(int pid)
    {
        var ppid = GetParentPidWindows(pid);
        if (ppid <= 0 || ppid == pid)
        {
            return (Unknown, 0);
        }

        try
        {
            var parentName = Process.GetProcessById(ppid).ProcessName;
            return (string.IsNullOrWhiteSpace(parentName) ? Unknown : parentName, ppid);
        }
        catch
        {
            return (Unknown, ppid);
        }
    }

    private static int GetParentPidMac(int pid)
    {
        const int ProcPidTBsdInfo = 3;
        const int BufferSize = 256;

        var buffer = Marshal.AllocHGlobal(BufferSize);
        try
        {
            var result = proc_pidinfo(pid, ProcPidTBsdInfo, 0, buffer, BufferSize);
            if (result <= 20)
            {
                return 0;
            }

            return Marshal.ReadInt32(buffer, 16);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int GetParentPidWindows(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var handle = process.Handle;

            var status = NtQueryInformationProcess(
                handle,
                0,
                out var processInformation,
                Marshal.SizeOf<ProcessBasicInformation>(),
                out _);

            if (status != 0)
            {
                return 0;
            }

            return (int)processInformation.InheritedFromUniqueProcessId;
        }
        catch
        {
            return 0;
        }
    }

    private static string GetProcessNameMac(int pid)
    {
        const int NameSize = 1024;
        var buffer = Marshal.AllocHGlobal(NameSize);
        try
        {
            var len = proc_name(pid, buffer, (uint)NameSize);
            if (len <= 0)
            {
                return string.Empty;
            }

            return Marshal.PtrToStringAnsi(buffer) ?? string.Empty;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("/usr/lib/libproc.dylib", EntryPoint = "proc_pidinfo")]
    private static extern int proc_pidinfo(
        int pid,
        int flavor,
        ulong arg,
        IntPtr buffer,
        int buffersize);

    [DllImport("/usr/lib/libproc.dylib", EntryPoint = "proc_name")]
    private static extern int proc_name(
        int pid,
        IntPtr buffer,
        uint buffersize);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        out ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);
}
