using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DotnetMuxer;

#if !DOTNETMUXER_LINUX && !DOTNETMUXER_DARWIN
internal static class WindowsHelper
{
    private const string Unknown = "unknown";

    internal static (string Name, int ParentPid) GetParentProcess(int pid)
    {
        var ppid = GetParentPid(pid);
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
