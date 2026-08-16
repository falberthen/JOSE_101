namespace JOSE_101.Core.Jws;

/// <summary>
/// JWS signing/verification using RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
/// </summary>
public static class JwsRsaFactory
{
    /// <summary>
    /// Signs <paramref name="payloadJson"/> with RS256 using the RSA private key.
    /// </summary>
    public static string Sign(string payloadJson, RSA privateKey)
        => JWT.Encode(payloadJson, privateKey, JwsAlgorithm.RS256);

    /// <summary>
    /// Verifies the RS256 signature using the RSA public key and returns the payload JSON.
    /// Verify() only accepts signed tokens, and the expected algorithm is passed explicitly, so a token declaring
    /// anything other than RS256 is rejected instead of dictating how it gets verified.
    /// </summary>
    public static string Verify(string token, RSA publicKey)
        => JWT.Verify(token, publicKey, JwsAlgorithm.RS256);
}
