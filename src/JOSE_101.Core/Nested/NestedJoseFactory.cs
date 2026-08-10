namespace JOSE_101.Core.Nested;

/// <summary>
/// Nested JOSE: signs a payload, then encrypts the resulting JWS as the payload of a JWE. 
/// Sets the outer header's "cty" to "JWT" so a compliant reader knows to decrypt-then-verify.
/// </summary>
public static class NestedJoseFactory
{
    private static readonly Dictionary<string, object> InnerJwtContentType = new() { { "cty", "JWT" } };

    /// <summary>
    /// Signs <paramref name="payloadJson"/> with <paramref name="signAlgorithm"/>,
    /// then encrypts the resulting JWS with <paramref name="encryptAlgorithm"/> (content encryption is always A256GCM).
    /// Key types must match the chosen algorithms.
    /// </summary>
    public static string SignThenEncrypt(
        string payloadJson, 
        JwsAlgorithm signAlgorithm, 
        object signingKey, 
        JweAlgorithm encryptAlgorithm, 
        object encryptionKey)
    {
        var innerJws = JWT.Encode(payloadJson, signingKey, signAlgorithm);
        return JWT.Encode(innerJws, encryptionKey, encryptAlgorithm, JweEncryption.A256GCM, extraHeaders: InnerJwtContentType);
    }
}
