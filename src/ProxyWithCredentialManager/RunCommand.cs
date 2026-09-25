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
        using var credentials = ProxyCredentialManager.Open(CredentialDatabase.FullName);
        using var proxy = ProxyServer.Start(ProxyPort, credentials);
        await CredentialManageServer.RunAsync(credentials, CredentialManagerPort);
    }
}
