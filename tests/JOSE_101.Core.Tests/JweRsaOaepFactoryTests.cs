namespace JOSE_101.Core.Tests;

public class JweRsaOaepFactoryTests
{
    [Fact]
    public void Encrypt_Then_Decrypt_ReturnsOriginalPayload()
    {
        using var key = RSA.Create(2048);
        var token = JweRsaOaepFactory.Encrypt("""{"sub":"alice"}""", key);

        var payload = JweRsaOaepFactory.Decrypt(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        using var encryptionKey = RSA.Create(2048);
        using var wrongKey = RSA.Create(2048);
        var token = JweRsaOaepFactory.Encrypt("""{"sub":"alice"}""", encryptionKey);

        Assert.ThrowsAny<Exception>(() 
            => JweRsaOaepFactory.Decrypt(token, wrongKey));
    }
}
