namespace JOSE_101.ConsoleApp;

/// <summary>
/// Demo keys loaded from /keys at startup. 
/// See keys/README.md — not for production use.
/// </summary>
public sealed class DemoKeys
{
    public required RSA RsaPrivate { get; init; }
    public required RSA RsaPublic { get; init; }
    public required ECDsa EcPrivate { get; init; }
    public required ECDsa EcPublic { get; init; }

    /// <summary>
    /// 256-bit secret shared by HS256 (JWS) and dir+A256GCM (JWE/Nested).
    /// </summary>
    public required byte[] SharedSecret { get; init; }
}

public static class KeyStore
{
    /// <summary>
    /// Walks up from <paramref name="start"/> until it finds JOSE_101.slnx, i.e. the repo root.
    /// </summary>
    public static string FindRepoRoot(string start)
    {
        for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "JOSE_101.slnx")))
                return dir.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate the repo root (JOSE_101.slnx) walking up from " + start);
    }

    public static DemoKeys Load(string keysDirectory)
    {
        var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(File.ReadAllText(Path.Combine(keysDirectory, "rsa-private.pem")));

        var rsaPublic = RSA.Create();
        rsaPublic.ImportFromPem(File.ReadAllText(Path.Combine(keysDirectory, "rsa-public.pem")));

        var ecPrivate = ECDsa.Create();
        ecPrivate.ImportFromPem(File.ReadAllText(Path.Combine(keysDirectory, "ec-private.pem")));

        var ecPublic = ECDsa.Create();
        ecPublic.ImportFromPem(File.ReadAllText(Path.Combine(keysDirectory, "ec-public.pem")));

        var sharedSecret = Convert.FromBase64String(File.ReadAllText(Path.Combine(keysDirectory, "hmac-secret.txt")).Trim());

        return new DemoKeys
        {
            RsaPrivate = rsaPrivate,
            RsaPublic = rsaPublic,
            EcPrivate = ecPrivate,
            EcPublic = ecPublic,
            SharedSecret = sharedSecret
        };
    }
}
