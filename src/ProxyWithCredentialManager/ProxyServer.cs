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

    public static ProxyServer Create(int port, DirectoryInfo proxyDirectory)
    {
        proxyDirectory.Create();
        var credentials = ProxyCredentialManager.Open(Path.Combine(proxyDirectory.FullName, "credentials.db"));

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

    private Task<bool> ValidateAsync(SessionEventArgsBase? session, string credentialId, string credential)
    {
        return Task.FromResult(this.Credentials.Verify(credentialId, credential));
    }

    public void Dispose()
    {
        this.server.Dispose();
        this.Credentials.Dispose();
    }
}
