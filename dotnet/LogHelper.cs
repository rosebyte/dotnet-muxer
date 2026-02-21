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

#if DOTNETMUXER_WINDOWS
        var (parentName, parentId) = WindowsHelper.GetParentProcess(pid);
#elif DOTNETMUXER_LINUX
        var (parentName, parentId) = LinuxHelper.GetParentProcess(pid);
#elif DOTNETMUXER_DARWIN
        var (parentName, parentId) = DarwinHelper.GetParentProcess(pid);
#else
    var (parentName, parentId) = (Unknown, 0);
#endif
            Write(sb, "parent", $"({parentId}) {parentName}");
            pid = parentId;
        }
    }
}
