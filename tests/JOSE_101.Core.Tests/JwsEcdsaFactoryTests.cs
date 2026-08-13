namespace JOSE_101.Core.Tests;

public class JwsEcdsaFactoryTests
{
    /// <summary>
    /// The private key signs and the matching public key verifies, so the payload survives the round trip untouched.
    /// </summary>
    [Fact]
    public void Sign_Then_Verify_ReturnsOriginalPayload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = JwsEcdsaFactory.Sign("""{"sub":"alice"}""", key);

        var payload = JwsEcdsaFactory.Verify(token, key);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    /// <summary>
    /// An unrelated key pair must not validate the signature, otherwise the signature would prove nothing about the signer.
    /// </summary>
    [Fact]
    public void Verify_WithWrongKey_Throws()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = JwsEcdsaFactory.Sign("""{"sub":"alice"}""", signingKey);

        Assert.ThrowsAny<Exception>(() 
            => JwsEcdsaFactory.Verify(token, wrongKey));
    }
}
