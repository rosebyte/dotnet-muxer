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

        var sb = new StringBuilder(Environment.CommandLine.Replace(Environment.NewLine, " "));
        Write(sb, "target", testHostPath);
        Write(sb, "cwd", Environment.CurrentDirectory);
        Write(sb, "process", $"({Environment.ProcessId}) {Environment.ProcessPath}");
        AddParents(sb, Environment.ProcessId);
        Write(sb, "ts", DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        sb.AppendLine();
        sb.AppendLine();

        var processPath = Environment.ProcessPath;
        var dir = processPath is null ? null : Path.GetDirectoryName(processPath);
        var logPath = Path.Combine(string.IsNullOrWhiteSpace(dir) ? "." : dir, "log.log");
        File.AppendAllText(logPath, sb.ToString());
    }

    private static void Write(StringBuilder sb, string key, string value)
    {
        sb.AppendLine();
        sb.Append("  ");
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
   
#if DOTNETMUXER_LINUX
            if (!LinuxHelper.TryGetParentProcess(pid, out var parentId, out var parentName))
            {
                break;
            }
#elif DOTNETMUXER_DARWIN
            if (!DarwinHelper.TryGetParentProcess(pid, out var parentId, out var parentName))
            {
                break;
            }
#else
            if (!WindowsHelper.TryGetParentProcess(pid, out var parentId, out var parentName))
            {
                break;
            }
#endif
            Write(sb, "parent", $"({parentId}) {parentName}");
            pid = parentId;
        }
    }
}
