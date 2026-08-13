namespace JOSE_101.Core.Tests;

public class JwsRsaFactoryTests
{
    /// <summary>
    /// The private key signs and the matching public key verifies, so the payload survives the round trip untouched.
    /// </summary>
    [Fact]
    public void Sign_Then_Verify_ReturnsOriginalPayload()
    {
        using var key = RSA.Create(2048);
        var token = JwsRsaFactory.Sign("""{"sub":"alice"}""", key);

        var payload = JwsRsaFactory.Verify(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    /// <summary>
    /// An unrelated key pair must not validate the signature, otherwise the signature would prove nothing about the signer.
    /// </summary>
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
