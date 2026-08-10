namespace JOSE_101.Core.Tests;

public class JoseInspectorTests
{
    [Fact]
    public void Inspect_JwsToken_ReturnsJwsTypeAndUnverifiedPayload()
    {
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));

        var result = JoseInspector.Inspect(token);

        Assert.Equal("JWS", result.TokenType);
        Assert.Equal("""{"sub":"alice"}""", result.UnverifiedPayload);
    }

    [Fact]
    public void Inspect_JweToken_ReturnsJweTypeAndNullPayload()
    {
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));

        var result = JoseInspector.Inspect(token);

        Assert.Equal("JWE", result.TokenType);
        Assert.Null(result.UnverifiedPayload);
    }
}
