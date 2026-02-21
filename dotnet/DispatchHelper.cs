using System.Diagnostics;

namespace DotnetMuxer;

internal static class DispatchHelper
{
    internal static int Execute(string dotnetPath, string[] args)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = dotnetPath,
            UseShellExecute = false
        };

        for (var i = 0; i < args.Length; i++)
        {
            startInfo.ArgumentList.Add(args[i]);
        }

        Process? process = null;
        try
        {
            process = Process.Start(startInfo);
            if (process is null)
            {
                Console.Error.WriteLine($"[dotnet-muxer] Failed to start {dotnetPath}.");
                return 2;
            }

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[dotnet-muxer] Failed to execute {dotnetPath}: {ex.Message}{FormatStackTrace(ex)}");
            return 3;
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static string FormatStackTrace(Exception exception)
    {
        var stackTrace = exception.StackTrace?.Trim().Replace(Environment.NewLine, $"{Environment.NewLine}[dotnet-muxer] ");
        return stackTrace is null ? string.Empty : $"{Environment.NewLine}{stackTrace}";
    }
}
