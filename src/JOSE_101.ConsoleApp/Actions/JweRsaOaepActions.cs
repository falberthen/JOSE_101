namespace JOSE_101.ConsoleApp.Actions;

/// <summary>JWE RSA-OAEP (RSA-OAEP + A256GCM) — encrypt and decrypt.</summary>
public sealed class JweRsaOaepActions : JweActionsBase
{
    private readonly DemoKeys keys;

    public JweRsaOaepActions(DemoKeys keys, ConsoleIO io) : base(io)
    {
        this.keys = keys;
    }

    protected override string Label => "RSA-OAEP+A256GCM";
    protected override string SampleTokenFile => "jwe-rsa-oaep.jwe";
    protected override string HintMessage => "Asymmetric key wrapping: a random per-message AES key is wrapped with the RSA public key — anyone with it can encrypt, only the private key decrypts.";
    protected override string SuccessMessage => "Decrypted with the RSA private key after unwrapping the content-encryption key.";
    protected override string DoEncrypt(string payloadJson) => JweRsaOaepFactory.Encrypt(payloadJson, keys.RsaPublic);
    protected override string DoDecrypt(string token) => JweRsaOaepFactory.Decrypt(token, keys.RsaPrivate);
}
