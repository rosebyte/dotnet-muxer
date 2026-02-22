using System.Runtime.InteropServices;

namespace DotnetMuxer;

#if !DOTNETMUXER_WINDOWS && !DOTNETMUXER_LINUX
internal static class DarwinHelper
{
    private const string Unknown = "unknown";

    internal static bool TryGetParentProcess(int pid, out int parentPid, out string parentName)
    {
        try
        {
            var ppid = GetParentPid(pid);
            if (ppid <= 0 || ppid == pid)
            {
                parentPid = 0;
                parentName = Unknown;
                return false;
            }

            var name = GetProcessName(ppid);
            if (ppid == 1 && string.Equals(name, "launchd", StringComparison.OrdinalIgnoreCase))
            {
                parentPid = 0;
                parentName = Unknown;
                return false;
            }

            parentPid = ppid;
            parentName = string.IsNullOrWhiteSpace(name) ? Unknown : name;
            return true;
        }
        catch
        {
            parentPid = 0;
            parentName = Unknown;
            return false;
        }
    }

    private static int GetParentPid(int pid)
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

    private static string GetProcessName(int pid)
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
}
#endif
