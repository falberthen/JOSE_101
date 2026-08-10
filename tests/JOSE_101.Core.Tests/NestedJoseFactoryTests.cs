namespace JOSE_101.Core.Tests;

public class NestedJoseFactoryTests
{
    [Fact]
    public void SignThenEncrypt_ThenDecryptAndVerify_ReturnsOriginalPayload()
    {
        var signingSecret = RandomNumberGenerator.GetBytes(32);
        var encryptionKey = RandomNumberGenerator.GetBytes(32);

        var token = NestedJoseFactory.SignThenEncrypt(
            """{"sub":"alice"}""", JwsAlgorithm.HS256, signingSecret, JweAlgorithm.DIR, encryptionKey);

        var innerJws = JweDirectFactory.Decrypt(token, encryptionKey);
        var payload = JwsHmacFactory.Verify(innerJws, signingSecret);

        Assert.Equal("""{"sub":"alice"}""", payload);
    }
}
