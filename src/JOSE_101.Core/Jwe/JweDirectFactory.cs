namespace JOSE_101.Core.Jwe;

/// <summary>
/// JWE encryption/decryption using "dir" (direct key agreement) with AES-256-GCM (A256GCM) content encryption.
/// </summary>
public static class JweDirectFactory
{
    /// <summary>
    /// Encrypts <paramref name="payloadJson"/> with dir+A256GCM using a 256-bit <paramref name="key"/>.
    /// </summary>
    public static string Encrypt(string payloadJson, byte[] key)
        => JWT.Encode(payloadJson, key, JweAlgorithm.DIR, JweEncryption.A256GCM);

    /// <summary>
    /// Decrypts the token with the same 256-bit <paramref name="key"/> and returns the payload JSON.
    /// The expected algorithms are passed explicitly so a token declaring anything other than
    /// dir+A256GCM is rejected instead of dictating how it gets decrypted.
    /// </summary>
    public static string Decrypt(string token, byte[] key)
        => JWT.Decode(token, key, JweAlgorithm.DIR, JweEncryption.A256GCM);
}
