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
        Write(sb, "ts", DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        sb.AppendLine();


        var processPath = Environment.ProcessPath;
        var dir = processPath is null ? null : Path.GetDirectoryName(processPath);
        var logPath = Path.Combine(dir, "log.log");
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
        while (pid != 0)
        {
            var parentName = ParentProcessName(pid);
            sb.AppendLine("  ");
            sb.Append("parent=\"");
            sb.Append(parentName);
            sb.Append("\" ");
            pid = ParentProcessId(pid);
        }
    }

    private static string ParentProcessName(int pid)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return Unknown;
        }

        var ppidRaw = RunPs($"-o ppid= -p {pid}");
        if (!int.TryParse(ppidRaw, out var ppid))
        {
            return Unknown;
        }

        var parent = RunPs($"-o comm= -p {ppid}");
        return string.IsNullOrWhiteSpace(parent) ? Unknown : parent;
    }

    private static string RunPs(string args)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "ps",
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
