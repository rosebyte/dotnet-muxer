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
        LogHelper.Run(targetPath, args);

        var exitCode = DispatchHelper.Execute(targetPath, args);
        return exitCode;
    }

    private static void TryGetTestHostPath(string[] args, ref string testHostPath)
    {
        if (args.Length == 0)
        {
            return;
        }

        var argument = args[0];
        if (!argument.EndsWith("vstest.console.dll", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

#if DOTNETMUXER_WINDOWS
        var dotnet = "dotnet.exe";
#else
        var dotnet = "dotnet";
#endif

        var repoRoot = testHostPath.Substring(0, testHostPath.Length - "/.dotnet/".Length - dotnet.Length);
        var sdkRoot = Path.Combine(repoRoot, ".dotnet", "sdk");
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
}
