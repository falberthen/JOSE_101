namespace JOSE_101.Core.Tests;

public class JwsHmacFactoryTests
{
    [Fact]
    public void Sign_Then_Verify_ReturnsOriginalPayload()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", secret);

        var payload = JwsHmacFactory.Verify(token, secret);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }

    [Fact]
    public void Verify_WithWrongSecret_Throws()
    {
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));
        var wrongSecret = RandomNumberGenerator.GetBytes(32);

        Assert.ThrowsAny<Exception>(() 
            => JwsHmacFactory.Verify(token, wrongSecret));
    }
}
