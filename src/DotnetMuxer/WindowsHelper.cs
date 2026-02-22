using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DotnetMuxer;

#if !DOTNETMUXER_LINUX && !DOTNETMUXER_DARWIN
internal static class WindowsHelper
{
    private const string Unknown = "unknown";

    internal static bool TryGetParentProcess(int pid, out int parentPid, out string parentName, out string parentPath)
    {
        var ppid = GetParentPid(pid);
        if (ppid <= 0 || ppid == pid)
        {
            parentPid = 0;
            parentName = Unknown;
            parentPath = Unknown;
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(ppid);
            var name = process.ProcessName;
            var path = Unknown;
            try
            {
                path = process.MainModule?.FileName ?? Unknown;
            }
            catch
            {
                path = Unknown;
            }

            parentPid = ppid;
            parentName = string.IsNullOrWhiteSpace(name) ? Unknown : name;
            parentPath = string.IsNullOrWhiteSpace(path) ? Unknown : path;
            return true;
        }
        catch
        {
            parentPid = ppid;
            parentName = Unknown;
            parentPath = Unknown;
            return true;
        }
    }

    private static int GetParentPid(int pid)
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
#endif
