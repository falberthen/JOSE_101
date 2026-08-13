namespace JOSE_101.Core.Tests;

public class JweRsaOaepFactoryTests
{
    /// <summary>
    /// The public key wraps the content key and the private key unwraps it, so the payload survives the round trip untouched.
    /// </summary>
    [Fact]
    public void Encrypt_Then_Decrypt_ReturnsOriginalPayload()
    {
        using var key = RSA.Create(2048);
        var token = JweRsaOaepFactory.Encrypt("""{"sub":"alice"}""", key);

        var payload = JweRsaOaepFactory.Decrypt(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    /// <summary>
    /// Only the holder of the matching private key can unwrap the content key, so an unrelated key pair must fail.
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        using var encryptionKey = RSA.Create(2048);
        using var wrongKey = RSA.Create(2048);
        var token = JweRsaOaepFactory.Encrypt("""{"sub":"alice"}""", encryptionKey);

        Assert.ThrowsAny<Exception>(()
            => JweRsaOaepFactory.Decrypt(token, wrongKey));
    }

    /// <summary>
    /// The RSA key is correct, only the OAEP hash differs (SHA-256 instead of SHA-1).
    /// Decryption must still be refused: the caller decides which algorithm is acceptable, not the token.
    /// </summary>
    [Fact]
    public void Decrypt_TokenDeclaringDifferentKeyManagement_Throws()
    {
        using var key = RSA.Create(2048);
        var token = JWT.Encode("""{"sub":"alice"}""", key, JweAlgorithm.RSA_OAEP_256, JweEncryption.A256GCM);

        Assert.ThrowsAny<Exception>(()
            => JweRsaOaepFactory.Decrypt(token, key));
    }
}
