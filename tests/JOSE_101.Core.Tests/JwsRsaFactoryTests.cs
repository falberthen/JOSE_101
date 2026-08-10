namespace JOSE_101.Core.Tests;

public class JwsRsaFactoryTests
{
    [Fact]
    public void Sign_Then_Verify_ReturnsOriginalPayload()
    {
        using var key = RSA.Create(2048);
        var token = JwsRsaFactory.Sign("""{"sub":"alice"}""", key);

        var payload = JwsRsaFactory.Verify(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    [Fact]
    public void Verify_WithWrongKey_Throws()
    {
        using var signingKey = RSA.Create(2048);
        using var wrongKey = RSA.Create(2048);
        var token = JwsRsaFactory.Sign("""{"sub":"alice"}""", signingKey);

        Assert.ThrowsAny<Exception>(() 
            => JwsRsaFactory.Verify(token, wrongKey));
    }
}
