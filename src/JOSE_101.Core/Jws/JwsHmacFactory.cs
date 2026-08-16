namespace JOSE_101.Core.Jws;

/// <summary>
/// JWS signing/verification using HMAC-SHA256 (HS256).
/// </summary>
public static class JwsHmacFactory
{
    /// <summary>
    /// Signs <paramref name="payloadJson"/> with HS256 using <paramref name="secret"/>.
    /// </summary>
    public static string Sign(string payloadJson, byte[] secret)
        => JWT.Encode(payloadJson, secret, JwsAlgorithm.HS256);

    /// <summary>
    /// Verifies the HS256 signature and returns the payload JSON. Throws if the token was tampered with or the secret doesn't match.
    /// Verify() only accepts signed tokens, and the expected algorithm is passed explicitly, so a token declaring
    /// anything other than HS256 is rejected instead of dictating how it gets verified.
    /// </summary>
    public static string Verify(string token, byte[] secret)
        => JWT.Verify(token, secret, JwsAlgorithm.HS256);
}
