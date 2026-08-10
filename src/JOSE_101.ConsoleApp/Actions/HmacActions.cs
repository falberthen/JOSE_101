namespace JOSE_101.ConsoleApp.Actions;

/// <summary>JWS HMAC (HS256) — create and verify.</summary>
public sealed class HmacActions : JwsActionsBase
{
    private readonly DemoKeys keys;

    public HmacActions(DemoKeys keys, ConsoleIO io) : base(io)
    {
        this.keys = keys;
    }

    protected override string FamilyName => "HMAC";
    protected override string Label => "HS256";
    protected override string SampleTokenFile => "jws-hmac.jwt";
    protected override string HintMessage => "Symmetric: the same secret signs and verifies, so every verifier must be trusted with it.";
    protected override string SuccessMessage => "HS256 signature verified with the shared secret.";
    protected override string DoSign(string payloadJson) => JwsHmacFactory.Sign(payloadJson, keys.SharedSecret);
    protected override string DoVerify(string token) => JwsHmacFactory.Verify(token, keys.SharedSecret);
}
