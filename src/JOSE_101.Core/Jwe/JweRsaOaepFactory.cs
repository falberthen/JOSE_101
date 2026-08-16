namespace JOSE_101.Core.Jwe;

/// <summary>
/// JWE encryption/decryption using RSA-OAEP for key wrapping with AES-256-GCM (A256GCM) for content.
/// </summary>
public static class JweRsaOaepFactory
{
    /// <summary>
    /// Encrypts <paramref name="payloadJson"/> for the holder of the RSA private key using RSA-OAEP + A256GCM.
    /// </summary>
    public static string Encrypt(string payloadJson, RSA publicKey)
        => JWT.Encode(payloadJson, publicKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);

    /// <summary>
    /// Decrypts the token with the RSA private key and returns the payload JSON.
    /// Decrypt() only accepts encrypted tokens, and the expected algorithms are passed explicitly, so a token
    /// declaring anything other than RSA-OAEP+A256GCM is rejected instead of dictating how it gets decrypted.
    /// </summary>
    public static string Decrypt(string token, RSA privateKey)
        => JWT.Decrypt(token, privateKey, JweAlgorithm.RSA_OAEP, JweEncryption.A256GCM);
}
