using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProxyWithCredentialManager;

public sealed class ProxyCredentialManager
{
    private readonly FileInfo file;
    private readonly ConcurrentDictionary<string, (byte[] Hash, DateTimeOffset? Expire)> entries = new();

    private ProxyCredentialManager(FileInfo file)
    {
        this.file = file;
    }

    public static async Task<ProxyCredentialManager> LoadAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        var manager = new ProxyCredentialManager(file);
        await manager.LoadAsync(cancellationToken);
        return manager;
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        if (!this.file.Exists)
            return;

        await using var stream = new FileStream(this.file.FullName, FileMode.Open, FileAccess.Read);
        var stored = await JsonSerializer.DeserializeAsync<Dictionary<string, (byte[] Hash, DateTimeOffset? Expire)>>(stream, cancellationToken: cancellationToken) ?? [];
        foreach (var (username, entry) in stored)
        {
            this.entries[username] = entry;
        }
    }

    public bool Verify(string username, string password)
    {
        if (!this.entries.TryGetValue(username, out var entry))
            return false;

        if (entry.Expire is { } expire && expire <= DateTimeOffset.UtcNow)
        {
            this.entries.TryRemove(username, out _);
            return false;
        }

        var actualHash = Hash(password);
        return CryptographicOperations.FixedTimeEquals(actualHash, entry.Hash);
    }

    public async Task<string> AddAsync(string username, DateTimeOffset? expire, CancellationToken cancellationToken = default)
    {
        var plainPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        this.entries[username] = (Hash(plainPassword), expire);
        await this.StoreAsync(cancellationToken);
        return plainPassword;
    }

    public async Task<DateTimeOffset?> QueryAsync(string username, CancellationToken cancellationToken = default)
    {
        if (!this.entries.TryGetValue(username, out var entry))
            return null;

        if (entry.Expire is { } expire && expire <= DateTimeOffset.UtcNow)
        {
            this.entries.TryRemove(username, out _);
            await this.StoreAsync(cancellationToken);
            return null;
        }

        return entry.Expire;
    }

    public async Task RemoveAsync(string username, CancellationToken cancellationToken = default)
    {
        this.entries.TryRemove(username, out _);
        await this.StoreAsync(cancellationToken);
    }

    private async Task StoreAsync(CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(this.file.FullName, FileMode.Create, FileAccess.Write);
        await JsonSerializer.SerializeAsync(stream, this.entries, cancellationToken: cancellationToken);
    }

    private static byte[] Hash(string password)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(password);
        return SHA256.HashData(bytes);
    }
}
