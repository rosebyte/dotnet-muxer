using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DotnetMuxer;

internal sealed class Logger
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

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return (Unknown, 0);
        }

        var ppidRaw = RunPs($"-o ppid= -p {pid}");
        if (!int.TryParse(ppidRaw, out var ppid) || ppid <= 0 || ppid == pid)
        {
            return (Unknown, 0);
        }

        var parent = RunPs($"-o comm= -p {ppid}");
        return (string.IsNullOrWhiteSpace(parent) ? Unknown : parent, ppid);
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

    private static string RunPs(string args)
    {
        return RunCommand("ps", args);
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

    private static string RunCommand(string fileName, string args)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return string.Empty;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output.Trim();
        }
        catch
        {
            return string.Empty;
        }
    }

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
