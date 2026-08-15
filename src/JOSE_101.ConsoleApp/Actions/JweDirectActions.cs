namespace JOSE_101.ConsoleApp.Actions;

/// <summary>JWE direct (dir + A256GCM) — encrypt and decrypt.</summary>
public sealed class JweDirectActions : JweActionsBase
{
    private readonly DemoKeys keys;

    public JweDirectActions(DemoKeys keys, ConsoleIO io) : base(io)
    {
        this.keys = keys;
    }

    protected override string Label => "dir+A256GCM";
    protected override string SampleTokenFile => "jwe-direct.jwe";
    protected override string HintMessage => "Symmetric: the shared secret is used directly as the content-encryption key, no per-message key wrapping.";
    protected override string SuccessMessage => "Decrypted with the shared secret (dir + A256GCM).";
    protected override string KeyPromptHint => "base64url-encoded secret";
    protected override string DoEncrypt(string payloadJson) => JweDirectFactory.Encrypt(payloadJson, keys.SharedSecret);
    protected override string DoDecrypt(string token) => JweDirectFactory.Decrypt(token, keys.SharedSecret);
    protected override string DoDecryptWithKey(string token, string keyInput) => JweDirectFactory.Decrypt(token, Base64Url.DecodeFromChars(keyInput.Trim()));
}
