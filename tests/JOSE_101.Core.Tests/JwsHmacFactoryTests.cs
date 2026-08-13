namespace JOSE_101.Core.Tests;

public class JwsHmacFactoryTests
{
    /// <summary>
    /// The same secret signs and verifies, so the payload survives the round trip untouched.
    /// </summary>
    [Fact]
    public void Sign_Then_Verify_ReturnsOriginalPayload()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", secret);

        var payload = JwsHmacFactory.Verify(token, secret);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    /// <summary>
    /// A signature only proves anything to whoever holds the same secret, so a different one must be rejected.
    /// </summary>
    [Fact]
    public void Verify_WithWrongSecret_Throws()
    {
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));
        var wrongSecret = RandomNumberGenerator.GetBytes(32);

        Assert.ThrowsAny<Exception>(() 
            => JwsHmacFactory.Verify(token, wrongSecret));
    }
}
