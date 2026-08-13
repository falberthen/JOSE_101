namespace JOSE_101.Core.Tests;

public class JweDirectFactoryTests
{
    /// <summary>
    /// The same 256-bit key encrypts and decrypts, so the payload survives the round trip untouched.
    /// </summary>
    [Fact]
    public void Encrypt_Then_Decrypt_ReturnsOriginalPayload()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", key);

        var payload = JweDirectFactory.Decrypt(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    /// <summary>
    /// Without the exact key the content stays opaque, which is the whole point of encrypting instead of signing.
    /// </summary>
    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));
        var wrongKey = RandomNumberGenerator.GetBytes(32);

        Assert.ThrowsAny<Exception>(()
            => JweDirectFactory.Decrypt(token, wrongKey));
    }

    /// <summary>
    /// The key is correct and of the right type, only the declared key-management algorithm differs.
    /// Decryption must still be refused: the caller decides which algorithm is acceptable, not the token.
    /// </summary>
    [Fact]
    public void Decrypt_TokenDeclaringDifferentKeyManagement_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var token = JWT.Encode("""{"sub":"alice"}""", key, JweAlgorithm.A256KW, JweEncryption.A256GCM);

        Assert.ThrowsAny<Exception>(()
            => JweDirectFactory.Decrypt(token, key));
    }

    /// <summary>
    /// The key and the declared key-management algorithm are both correct, only the content encryption differs.
    /// Decryption must still be refused: the caller decides which algorithm is acceptable.
    /// </summary>
    [Fact]
    public void Decrypt_TokenDeclaringDifferentContentEncryption_Throws()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var token = JWT.Encode("""{"sub":"alice"}""", key, JweAlgorithm.DIR, JweEncryption.A128CBC_HS256);

        Assert.ThrowsAny<Exception>(()
            => JweDirectFactory.Decrypt(token, key));
    }
}
