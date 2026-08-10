namespace JOSE_101.Core.Jws;

/// <summary>
/// JWS signing/verification using ECDSA with curve P-256 and SHA-256 (ES256).
/// </summary>
public static class JwsEcdsaFactory
{
    /// <summary>
    /// Signs <paramref name="payloadJson"/> with ES256 using the EC private key.
    /// </summary>
    public static string Sign(string payloadJson, ECDsa privateKey)
        => JWT.Encode(payloadJson, privateKey, JwsAlgorithm.ES256);

    /// <summary>
    /// Verifies the ES256 signature using the EC public key and returns the payload JSON.
    /// </summary>
    public static string Verify(string token, ECDsa publicKey)
        => JWT.Decode(token, publicKey, JwsAlgorithm.ES256);
}
