namespace DotnetMuxer;

#if !DOTNETMUXER_WINDOWS && !DOTNETMUXER_DARWIN
internal static class LinuxHelper
{
    private const string Unknown = "unknown";

    internal static (string Name, int ParentPid) GetParentProcess(int pid)
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
}
#endif
