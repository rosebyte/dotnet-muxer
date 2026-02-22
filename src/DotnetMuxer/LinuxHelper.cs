namespace DotnetMuxer;

#if !DOTNETMUXER_WINDOWS && !DOTNETMUXER_DARWIN
internal static class LinuxHelper
{
    private const string Unknown = "unknown";

    internal static bool TryGetParentProcess(int pid, out int parentPid, out string parentName, out string parentPath)
    {
        try
        {
            var statusPath = $"/proc/{pid}/status";
            if (!File.Exists(statusPath))
            {
                parentPid = 0;
                parentName = Unknown;
                parentPath = Unknown;
                return false;
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
                    parentPid = 0;
                    parentName = Unknown;
                    parentPath = Unknown;
                    return false;
                }

                break;
            }

            if (ppid <= 0)
            {
                parentPid = 0;
                parentName = Unknown;
                parentPath = Unknown;
                return false;
            }

            var commPath = $"/proc/{ppid}/comm";
            var name = File.Exists(commPath) ? File.ReadAllText(commPath).Trim() : Unknown;
            var path = Unknown;
            var exeLinkPath = $"/proc/{ppid}/exe";
            if (File.Exists(exeLinkPath))
            {
                try
                {
                    path = File.ResolveLinkTarget(exeLinkPath, true)?.FullName ?? Unknown;
                }
                catch
                {
                    path = Unknown;
                }
            }

            parentPid = ppid;
            parentName = string.IsNullOrWhiteSpace(name) ? Unknown : name;
            parentPath = string.IsNullOrWhiteSpace(path) ? Unknown : path;
            return true;
        }
        catch
        {
            parentPid = 0;
            parentName = Unknown;
            parentPath = Unknown;
            return false;
        }
    }
}
#endif
