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

    [CommandOption("credential-database")]
    public required FileInfo CredentialDatabase { get; set; }

    public async ValueTask ExecuteAsync(IConsole console)
    {
        using var proxy = ProxyServer.Create(ProxyPort, CredentialDatabase.FullName);
        await using var credentialManageServer = await CredentialManageServer.StartAsync(
            proxy.Credentials, CredentialManagerPort);

        await console.Output.WriteLineAsync($"Proxy listening on 127.0.0.1:{ProxyPort}");
        await console.Output.WriteLineAsync($"Credential manager API listening on 127.0.0.1:{CredentialManagerPort}");

        await Task.Delay(Timeout.Infinite, console.RegisterCancellationHandler());
    }
}
