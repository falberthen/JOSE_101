namespace JOSE_101.ConsoleApp.Actions;

/// <summary>JWS RSA (RS256) — create and verify.</summary>
public sealed class RsaActions : JwsActionsBase
{
    private readonly DemoKeys keys;

    public RsaActions(DemoKeys keys, ConsoleIO io) : base(io)
    {
        this.keys = keys;
    }

    protected override string FamilyName => "RSA";
    protected override string Label => "RS256";
    protected override string SampleTokenFile => "jws-rsa.jwt";
    protected override string HintMessage => "Asymmetric: the private key signs, the public key verifies — safe to hand the public key to untrusted verifiers.";
    protected override string SuccessMessage => "RS256 signature verified with the RSA public key.";
    protected override string DoSign(string payloadJson) => JwsRsaFactory.Sign(payloadJson, keys.RsaPrivate);
    protected override string DoVerify(string token) => JwsRsaFactory.Verify(token, keys.RsaPublic);
}
