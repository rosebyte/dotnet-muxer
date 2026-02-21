using System.Diagnostics;

namespace DotnetMuxer;

internal static class Program
{
    private const string DotnetMuxerTarget = "DOTNET_MUXER_TARGET";

    private static int Main(string[] args)
    {
        var targetPath = Environment.GetEnvironmentVariable(DotnetMuxerTarget);
        if (string.IsNullOrEmpty(targetPath))
        {
            Console.Error.WriteLine($"[dotnet-muxer] {DotnetMuxerTarget} is not set");
            return 1;
        }

        TryGetTestHostPath(args, ref targetPath);
        var exitCode = Execute(targetPath, args);
        Logger.Run(targetPath, args);
        return exitCode;
    }

    private static void TryGetTestHostPath(string[] args, ref string testHostPath)
    {
        if (args.Length < 1)
        {
            return;
        }

        var argument = args[0];
        if (!argument.EndsWith("vstest.console.dll", StringComparison.OrdinalIgnoreCase))
        {
            return; 
        }

        var repoRoot = testHostPath.Substring(0, testHostPath.Length - "/.dotnet/dotnet".Length);
        var sdkRoot = repoRoot + "/.dotnet/sdk";
        argument = Path.GetFullPath(argument);
        if (!argument.StartsWith(sdkRoot, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var testhostDir = Path.Combine(repoRoot, "artifacts", "bin", "testhost");
        if (!Directory.Exists(testhostDir))
        {
            return;
        }

        var dotnet = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        foreach (var entry in Directory.EnumerateDirectories(testhostDir))
        {
            var candidate = Path.Combine(entry, dotnet);
            if (!File.Exists(candidate))
            {
                continue;
            }

            testHostPath = candidate;

            if (candidate.Contains("Release", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }
    }

    private static int Execute(string dotnetPath, string[] args)
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

        try
        {
            using var process = Process.Start(startInfo);
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
    }

    private static string FormatStackTrace(Exception exception)
    {
        var stackTrace = exception.StackTrace?.Trim().Replace(Environment.NewLine, $"{Environment.NewLine}[dotnet-muxer] ");
        return stackTrace is null ? string.Empty : $"{Environment.NewLine}{stackTrace}";
    }
}
