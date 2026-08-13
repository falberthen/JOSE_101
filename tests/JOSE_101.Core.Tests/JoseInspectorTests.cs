namespace JOSE_101.Core.Tests;

public class JoseInspectorTests
{
    /// <summary>
    /// A JWS payload is only encoded, never encrypted, so inspection can read it without any key at all.
    /// </summary>
    [Fact]
    public void Inspect_JwsToken_ReturnsJwsTypeAndUnverifiedPayload()
    {
        var token = JwsHmacFactory.Sign("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));

        var result = JoseInspector.Inspect(token);

        Assert.Equal("JWS", result.TokenType);
        Assert.Equal("""{"sub":"alice"}""", result.UnverifiedPayload);
    }

    /// <summary>
    /// A JWE payload is ciphertext, so inspection can identify the token type but has nothing readable to return.
    /// </summary>
    [Fact]
    public void Inspect_JweToken_ReturnsJweTypeAndNullPayload()
    {
        var token = JweDirectFactory.Encrypt("""{"sub":"alice"}""", RandomNumberGenerator.GetBytes(32));

        var result = JoseInspector.Inspect(token);

        Assert.Equal("JWE", result.TokenType);
        Assert.Null(result.UnverifiedPayload);
    }
}
