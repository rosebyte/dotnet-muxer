using System.Diagnostics;
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
        var ppidRaw = RunPowerShell($"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').ParentProcessId");
        if (!int.TryParse(ppidRaw, out var ppid) || ppid <= 0 || ppid == pid)
        {
            return (Unknown, 0);
        }

        var parentName = RunPowerShell($"(Get-Process -Id {ppid} -ErrorAction SilentlyContinue).ProcessName");
        return (string.IsNullOrWhiteSpace(parentName) ? Unknown : parentName, ppid);
    }

    private static string RunPs(string args)
    {
        return RunCommand("ps", args);
    }

    private static string RunPowerShell(string command)
    {
        return RunCommand("powershell", $"-NoProfile -NonInteractive -Command \"{command}\"");
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
}
