using CliFx;
using CliFx.Binding;
using CliFx.Infrastructure;

namespace ProxyWithCredentialManager;

[Command("run")]
public sealed partial class RunCommand : ICommand
{
    [CommandOption("proxy-port")]
    public required int ProxyPort { get; set; }

    [CommandOption("credential-manager-port")]
    public required int CredentialManagerPort { get; set; }

    [CommandOption("data-directory")]
    public required string DataDirectory { get; set; }

    public async ValueTask ExecuteAsync(IConsole console)
    {
        var dataDirectory = new DirectoryInfo(DataDirectory);

        using var proxy = await ProxyServer.CreateAsync(
            ProxyPort,
            new DirectoryInfo(Path.Combine(dataDirectory.FullName, "proxy")));
        await using var credentialManageServer = await CredentialManageServer.StartAsync(
            proxy.Credentials, CredentialManagerPort);

        await console.Output.WriteLineAsync($"Proxy listening on 127.0.0.1:{ProxyPort}");
        await console.Output.WriteLineAsync($"Credential manager API listening on 127.0.0.1:{CredentialManagerPort}");

        await Task.Delay(Timeout.Infinite, console.RegisterCancellationHandler());
    }
}
