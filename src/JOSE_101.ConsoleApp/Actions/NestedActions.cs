namespace JOSE_101.ConsoleApp.Actions;

/// <summary>Nested JWT (sign then encrypt) — the only action family that lets the caller pick both a JWS and a JWE algorithm.</summary>
public sealed class NestedActions
{
    private const string Hmac = "hmac";
    private const string Rsa = "rsa";
    private const string Ecdsa = "ecdsa";
    private const string Dir = "dir";
    private const string RsaOaep = "rsa-oaep";

    private readonly DemoKeys keys;
    private readonly ConsoleIO io;

    public NestedActions(DemoKeys keys, ConsoleIO io)
    {
        this.keys = keys;
        this.io = io;
    }

    public void Create()
    {
        var payload = io.LoadPayload("payloads/claims-basic.json");
        var signWith = ConsoleIO.AskAlgorithm("Sign with", Hmac, Rsa, Ecdsa);
        var encryptWith = ConsoleIO.AskAlgorithm("Encrypt with", Dir, RsaOaep);

        var (signAlg, signingKey) = ResolveSigningForCreate(signWith);
        var (encAlg, encryptionKey) = ResolveEncryptionForCreate(encryptWith);

        var token = NestedJoseFactory.SignThenEncrypt(JsonSerializer.Serialize(payload), signAlg, signingKey, encAlg, encryptionKey);
        ResultRenderer.RenderJwe(token, "New Nested JWT (outer JWE — inner JWS is inside the ciphertext)");
        ResultRenderer.RenderSummary($"{SignLabel(signWith)} (inner JWS) + {EncLabel(encryptWith)} (outer JWE)", payload, token);
        AnsiConsole.MarkupLine("\n[grey]Signed then encrypted — the outer header's cty: JWT marks the decrypted payload as itself a JWT.[/]");
    }

    public void Unwrap()
    {
        var token = io.GetToken("nested-jws-then-jwe.jwe");
        var signWith = ConsoleIO.AskAlgorithm("Sign with (must match how the token was created)", Hmac, Rsa, Ecdsa);
        var encryptWith = ConsoleIO.AskAlgorithm("Encrypt with (must match how the token was created)", Dir, RsaOaep);

        ConsoleIO.Attempt(() =>
        {
            ResultRenderer.RenderJwe(token, "Outer JWE (encrypted)");
            ResultRenderer.RenderStep("Decrypting outer JWE...");

            string innerJws = encryptWith switch
            {
                Dir => JweDirectFactory.Decrypt(token, keys.SharedSecret),
                RsaOaep => JweRsaOaepFactory.Decrypt(token, keys.RsaPrivate),
                _ => throw new ArgumentException($"Unknown encryptWith: {encryptWith}")
            };
            ResultRenderer.RenderSuccess("Outer JWE decrypted — inner JWS revealed:");
            ResultRenderer.RenderJws(innerJws, "Inner JWS (now visible)");

            ResultRenderer.RenderStep("Verifying inner JWS signature...");
            string payloadJson = signWith switch
            {
                Hmac => JwsHmacFactory.Verify(innerJws, keys.SharedSecret),
                Rsa => JwsRsaFactory.Verify(innerJws, keys.RsaPublic),
                Ecdsa => JwsEcdsaFactory.Verify(innerJws, keys.EcPublic),
                _ => throw new ArgumentException($"Unknown signWith: {signWith}")
            };
            ResultRenderer.RenderSuccess("Inner JWS signature verified.");

            var payload = ConsoleIO.ParsePayload(payloadJson);
            ResultRenderer.RenderSummaryWithPayload($"{SignLabel(signWith)} (inner JWS) + {EncLabel(encryptWith)} (outer JWE)", payload, token, "DECRYPTED / VERIFIED PAYLOAD");
            AnsiConsole.MarkupLine("\n[grey]signWith/encryptWith were supplied by you, not read from the token's own header — trusting a token's self-declared algorithm is exactly the 'alg confusion' class of JWT vulnerability.[/]");
        });
    }

    private (JwsAlgorithm, object) ResolveSigningForCreate(string signWith) => signWith switch
    {
        Hmac => (JwsAlgorithm.HS256, (object)keys.SharedSecret),
        Rsa => (JwsAlgorithm.RS256, keys.RsaPrivate),
        Ecdsa => (JwsAlgorithm.ES256, keys.EcPrivate),
        _ => throw new ArgumentException($"Unknown signWith: {signWith}")
    };

    private (JweAlgorithm, object) ResolveEncryptionForCreate(string encryptWith) => encryptWith switch
    {
        Dir => (JweAlgorithm.DIR, (object)keys.SharedSecret),
        RsaOaep => (JweAlgorithm.RSA_OAEP, keys.RsaPublic),
        _ => throw new ArgumentException($"Unknown encryptWith: {encryptWith}")
    };

    private static string SignLabel(string signWith) =>
        signWith switch { Hmac => "HS256", Rsa => "RS256", Ecdsa => "ES256", _ => signWith };

    private static string EncLabel(string encryptWith) =>
        encryptWith switch { Dir => "dir+A256GCM", RsaOaep => "RSA-OAEP+A256GCM", _ => encryptWith };
}
