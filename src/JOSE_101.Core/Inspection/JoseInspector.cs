namespace JOSE_101.Core.Inspection;

/// <summary>
/// Result of inspecting a JOSE token's structure without verifying or decrypting it.
/// </summary>
/// <param name="TokenType">"JWS" (3 segments — signed, payload readable) or "JWE" (5 segments — encrypted, payload opaque).</param>
/// <param name="Header">The decoded JOSE header (alg, enc, typ, cty, ...).</param>
/// <param name="UnverifiedPayload">For JWS only: the payload as sent, decoded but NOT signature-checked. Null for JWE, since the payload is ciphertext.</param>
public sealed record JoseInspectionResult(
    string TokenType, 
    IDictionary<string, object> Header, 
    string? UnverifiedPayload);

/// <summary>
/// Reads a token's header (and, for JWS, its payload) without verifying a signature or decrypting anything.
/// </summary>
public static class JoseInspector
{
    /// <summary>
    /// Inspects <paramref name="token"/> and returns its header plus (for JWS) its unverified payload.
    /// </summary>
    public static JoseInspectionResult Inspect(string token)
    {
        var segments = token.Split('.');
        var header = JWT.Headers(token);

        // A JWS compact token has 3 segments (header.payload.signature).
        // A JWE has 5 (header.encryptedKey.iv.ciphertext.tag).
        // A JWS payload is plaintext.
        if (segments.Length == 3)
        {
            var payload = JWT.Payload(token);
            return new JoseInspectionResult("JWS", header, payload);
        }

        return new JoseInspectionResult("JWE", header, null);
    }
}
