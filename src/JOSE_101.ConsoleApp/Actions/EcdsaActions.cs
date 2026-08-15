namespace JOSE_101.ConsoleApp.Actions;

/// <summary>JWS ECDSA (ES256) — create and verify.</summary>
public sealed class EcdsaActions : JwsActionsBase
{
    private readonly DemoKeys keys;

    public EcdsaActions(DemoKeys keys, ConsoleIO io) : base(io)
    {
        this.keys = keys;
    }

    protected override string FamilyName => "ECDSA";
    protected override string Label => "ES256";
    protected override string SampleTokenFile => "jws-ecdsa.jwt";
    protected override string HintMessage => "Asymmetric like RS256, but much smaller keys/signatures for the same security level.";
    protected override string SuccessMessage => "ES256 signature verified with the EC public key.";
    protected override string KeyPromptHint => "EC public key (PEM)";
    protected override string DoSign(string payloadJson) => JwsEcdsaFactory.Sign(payloadJson, keys.EcPrivate);
    protected override string DoVerify(string token) => JwsEcdsaFactory.Verify(token, keys.EcPublic);

    protected override string DoVerifyWithKey(string token, string keyInput)
    {
        var ec = ECDsa.Create();
        ec.ImportFromPem(keyInput.Trim());
        return JwsEcdsaFactory.Verify(token, ec);
    }
}
