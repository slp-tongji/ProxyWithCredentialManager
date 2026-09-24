using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Tjslp.CredentialManager.Protocol;

namespace ProxyWithCredentialManager;

public sealed class CredentialManageServer : IAsyncDisposable
{
    private readonly ProxyCredentialManager proxyCredentials;
    private readonly WebApplication app;

    private CredentialManageServer(ProxyCredentialManager proxyCredentials, WebApplication app)
    {
        this.proxyCredentials = proxyCredentials;
        this.app = app;
    }

    public static async Task<CredentialManageServer> StartAsync(
        ProxyCredentialManager proxyCredentials, int port)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());

        builder.Services.AddRouting();
        builder.WebHost.UseKestrel(kestrel => kestrel.ListenLocalhost(port));

        var app = builder.Build();

        var server = new CredentialManageServer(proxyCredentials, app);

        app.MapPost("/create", server.HandleCreate);
        app.MapPost("/query", server.HandleQuery);
        app.MapPost("/revoke", server.HandleRevoke);

        await app.StartAsync();
        return server;
    }

    private CreateResponse HandleCreate(CreateRequest request)
    {
        var credentialId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        var proxyPassword = this.proxyCredentials.Add(credentialId, request.Expire);

        return new CreateResponse(credentialId, proxyPassword, request.Expire);
    }

    private QueryResponse HandleQuery(QueryRequest request)
    {
        var items = new List<QueryItem>();
        foreach (var credentialId in request.CredentialIds)
        {
            var expire = this.proxyCredentials.Query(credentialId);
            if (expire is not null)
            {
                items.Add(new QueryItem(credentialId, expire));
            }
        }

        return new QueryResponse(items);
    }

    private RevokeResponse HandleRevoke(RevokeRequest request)
    {
        this.proxyCredentials.Remove(request.CredentialId);
        return new RevokeResponse(true);
    }

    public async ValueTask DisposeAsync()
    {
        await this.app.DisposeAsync();
    }
}
