using System.Net;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace ProxyWithCredentialManager;

public sealed class ProxyServer : IDisposable
{
    private readonly Titanium.Web.Proxy.ProxyServer server;
    private readonly ProxyCredentialManager credentials;

    private ProxyServer(Titanium.Web.Proxy.ProxyServer server, ProxyCredentialManager credentials)
    {
        this.server = server;
        this.credentials = credentials;
    }

    public static ProxyServer Start(int port, ProxyCredentialManager credentials)
    {
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
        return Task.FromResult(this.credentials.Verify(credential));
    }

    public void Dispose()
    {
        this.server.Dispose();
    }
}
