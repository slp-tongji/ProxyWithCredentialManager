using System.Security.Cryptography;
using LiteDB;

namespace ProxyWithCredentialManager;

public sealed class ProxyCredentialManager : IDisposable
{
    private readonly LiteDatabase database;
    private readonly ILiteCollection<CredentialEntry> entries;

    private sealed class CredentialEntry
    {
        [BsonId]
        public string Username { get; set; } = "";

        public byte[] Hash { get; set; } = [];

        public DateTime? Expire { get; set; }
    }

    private ProxyCredentialManager(LiteDatabase database)
    {
        this.database = database;
        this.entries = database.GetCollection<CredentialEntry>("credentials");
    }

    public static ProxyCredentialManager Open(string filePath)
    {
        var database = new LiteDatabase(filePath);
        return new ProxyCredentialManager(database);
    }

    public bool Verify(string username, string password)
    {
        var entry = this.entries.FindById(username);
        if (entry is null)
            return false;

        if (entry.Expire is { } expire && expire <= DateTime.UtcNow)
        {
            this.entries.Delete(username);
            return false;
        }

        var actualHash = Hash(password);
        return CryptographicOperations.FixedTimeEquals(actualHash, entry.Hash);
    }

    public string Add(string username, DateTimeOffset? expire)
    {
        var plainPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        this.entries.Upsert(new CredentialEntry
        {
            Username = username,
            Hash = Hash(plainPassword),
            Expire = expire?.UtcDateTime,
        });
        return plainPassword;
    }

    public DateTimeOffset? Query(string username)
    {
        var entry = this.entries.FindById(username);
        if (entry is null)
            return null;

        if (entry.Expire is { } expire && expire <= DateTime.UtcNow)
        {
            this.entries.Delete(username);
            return null;
        }

        return entry.Expire is { } e ? new DateTimeOffset(e, TimeSpan.Zero) : null;
    }

    public void Remove(string username)
    {
        this.entries.Delete(username);
    }

    public void Dispose()
    {
        this.database.Dispose();
    }

    private static byte[] Hash(string password)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(password);
        return SHA256.HashData(bytes);
    }
}
