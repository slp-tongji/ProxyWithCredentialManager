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
        public required string CredentialId { get; set; }

        public required byte[] CredentialHash { get; set; }

        public DateTimeOffset? Expire { get; set; }
    }

    private ProxyCredentialManager(LiteDatabase database)
    {
        this.database = database;
        this.entries = database.GetCollection<CredentialEntry>("credentials");
        this.entries.EnsureIndex(x => x.CredentialHash, unique: true);
    }

    public static ProxyCredentialManager Open(string filePath)
    {
        var database = new LiteDatabase(filePath);
        return new ProxyCredentialManager(database);
    }

    public bool Verify(string credential)
    {
        var hash = Hash(credential);
        var entry = this.entries.Query().Where(x => x.CredentialHash == hash).SingleOrDefault();
        if (entry is null)
            return false;

        if (entry.Expire is { } expire && expire <= DateTimeOffset.UtcNow)
        {
            this.entries.Delete(entry.CredentialId);
            return false;
        }

        return true;
    }

    public string Add(string credentialId, DateTimeOffset? expire)
    {
        var plainPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        this.entries.Upsert(new CredentialEntry
        {
            CredentialId = credentialId,
            CredentialHash = Hash(plainPassword),
            Expire = expire,
        });
        return plainPassword;
    }

    public (bool Exists, DateTimeOffset? Expire) Query(string credentialId)
    {
        var entry = this.entries.FindById(credentialId);
        if (entry is null)
            return (false, null);

        if (entry.Expire is { } expire && expire <= DateTimeOffset.UtcNow)
        {
            this.entries.Delete(credentialId);
            return (false, null);
        }

        return (true, entry.Expire);
    }

    public void Remove(string credentialId)
    {
        this.entries.Delete(credentialId);
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
