namespace JOSE_101.Core.Tests;

public class JweDirectFactoryTests
{
    [Fact]
    public void Encrypt_Then_Decrypt_ReturnsOriginalPayload()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", key);

        var payload = JweDirectFactory.Decrypt(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Throws()
    {
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));
        var wrongKey = RandomNumberGenerator.GetBytes(32);

        Assert.ThrowsAny<Exception>(() 
            => JweDirectFactory.Decrypt(token, wrongKey));
    }
}
