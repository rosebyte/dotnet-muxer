using System.Diagnostics;
using System.Text;

namespace DotnetMuxer;

internal sealed class LogEntry : IDisposable
{
    internal const string TimestampFallback = "????-??-??T??:??:??Z";

    internal const string Unknown = "unknown";
    
    private readonly StreamWriter _writer;
    private readonly string _parentName;
    private readonly string _args;
    private readonly string _cwd;
    private readonly int _pid;
    private readonly List<string> _messages;
    private string? _target;

    private LogEntry(StreamWriter writer)
    {
        _pid = Environment.ProcessId;
        _writer = writer;
        _parentName = ParentProcessName(_pid);
        _args = string.Join(" ", Environment.GetCommandLineArgs());
        _cwd = Environment.CurrentDirectory;
        _messages = new List<string>();
    }

    public static bool IsVerboseEnabled()
    {
        var verbose = Environment.GetEnvironmentVariable("DOTNET_MUXER_VERBOSE");
        if (verbose is null)
        {
            return false;
        }

        return (verbose.Length == 1 && verbose[0] == '1')
            || string.Equals(verbose, "true", StringComparison.OrdinalIgnoreCase);
    }

    public static LogEntry? CreateIfVerbose()
    {
        if (!IsVerboseEnabled())
        {
            return null;
        }

        var writer = CreateWriter();
        return writer is null ? null : new LogEntry(writer);
    }

    public void Msg(string msg)
    {
        _messages.Add(msg);
    }

    public void Dispatch(string path)
    {
        _target = path;
    }

    public void Dispose()
    {
        Flush();
        _writer.Dispose();
    }

    private static StreamWriter? CreateWriter()
    {
        try
        {
            var processPath = Environment.ProcessPath;
            var dir = processPath is null ? null : Path.GetDirectoryName(processPath);
            if (string.IsNullOrWhiteSpace(dir))
            {
                return null;
            }

            var logPath = Path.Combine(dir, "log.log");
            var stream = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            return new StreamWriter(stream, new UTF8Encoding(false));
        }
        catch
        {
            return null;
        }
    }

    private void Flush()
    {
        var ts = Timestamp();
        var target = _target ?? "none";
        var msgs = _messages.Count == 0 ? string.Empty : $" messages=\"{string.Join("; ", _messages)}\"";
        _writer.WriteLine($"ts={ts} parent=\"{_parentName}\" pid={_pid} cwd=\"{_cwd}\" args=\"{_args}\" target=\"{target}\"{msgs}");
        _writer.Flush();
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

    private static string Timestamp()
    {
        try
        {
            return DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
        catch
        {
            return TimestampFallback;
        }
    }
}
