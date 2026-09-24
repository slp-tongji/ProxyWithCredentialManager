using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using ProxyWithCredentialManager.Proxy;
using Tjslp.CredentialManager.Protocol;

namespace ProxyWithCredentialManager.CredentialManagement;

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

        app.MapPost("/create", server.HandleCreateAsync);
        app.MapPost("/query", server.HandleQueryAsync);
        app.MapPost("/revoke", server.HandleRevokeAsync);

        await app.StartAsync();
        return server;
    }

    private async Task<CreateResponse> HandleCreateAsync(CreateRequest request, CancellationToken cancellationToken)
    {
        var credentialId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        var proxyPassword = await this.proxyCredentials.AddAsync(credentialId, request.Expire, cancellationToken);

        return new CreateResponse(credentialId, proxyPassword, request.Expire);
    }

    private async Task<QueryResponse> HandleQueryAsync(QueryRequest request, CancellationToken cancellationToken)
    {
        var items = new List<QueryItem>();
        foreach (var credentialId in request.CredentialIds)
        {
            var expire = await this.proxyCredentials.QueryAsync(credentialId, cancellationToken);
            if (expire is not null)
            {
                items.Add(new QueryItem(credentialId, expire));
            }
        }

        return new QueryResponse(items);
    }

    private async Task<RevokeResponse> HandleRevokeAsync(RevokeRequest request, CancellationToken cancellationToken)
    {
        await this.proxyCredentials.RemoveAsync(request.CredentialId, cancellationToken);
        return new RevokeResponse(true);
    }

    public async ValueTask DisposeAsync()
    {
        await this.app.DisposeAsync();
    }
}
