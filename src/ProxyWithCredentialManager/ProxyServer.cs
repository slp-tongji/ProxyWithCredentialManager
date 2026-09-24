using System.Net;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace ProxyWithCredentialManager;

public sealed class ProxyServer : IDisposable
{
    private readonly Titanium.Web.Proxy.ProxyServer server;

    private ProxyServer(Titanium.Web.Proxy.ProxyServer server, ProxyCredentialManager credentials)
    {
        this.server = server;
        this.Credentials = credentials;
    }

    public ProxyCredentialManager Credentials { get; }

    public static async Task<ProxyServer> CreateAsync(int port, DirectoryInfo proxyDirectory, CancellationToken cancellationToken = default)
    {
        proxyDirectory.Create();
        var credentialsFile = new FileInfo(Path.Combine(proxyDirectory.FullName, "credentials.json"));

        var credentials = await ProxyCredentialManager.LoadAsync(credentialsFile, cancellationToken);

        var server = new Titanium.Web.Proxy.ProxyServer(
            userTrustRootCertificate: false,
            machineTrustRootCertificate: false,
            trustRootCertificateAsAdmin: false);

        var proxy = new ProxyServer(server, credentials);

        server.ProxyBasicAuthenticateFunc = proxy.ValidateAsync;

        var endPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, port, decryptSsl: false);
        server.AddEndPoint(endPoint);
        server.Start(changeSystemProxySettings: false);

        return proxy;
    }

    private Task<bool> ValidateAsync(SessionEventArgsBase? session, string username, string password)
        => Task.FromResult(this.Credentials.Verify(username, password));

    public void Dispose()
    {
        this.server.Dispose();
    }
}
