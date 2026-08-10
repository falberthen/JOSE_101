namespace JOSE_101.ConsoleApp.Actions;

/// <summary>Template for JWE encrypt/decrypt — shared prompt/render orchestration. Each mode subclass supplies only its key-specific encrypt/decrypt calls and didactic labels (Open/Closed: a new JWE mode is a new subclass, no changes here).</summary>
public abstract class JweActionsBase
{
    protected readonly ConsoleIO io;

    protected JweActionsBase(ConsoleIO io)
    {
        this.io = io;
    }

    protected abstract string Label { get; }
    protected abstract string SampleTokenFile { get; }
    protected abstract string HintMessage { get; }
    protected abstract string SuccessMessage { get; }
    protected abstract string DoEncrypt(string payloadJson);
    protected abstract string DoDecrypt(string token);

    public void Encrypt()
    {
        var payload = io.LoadPayload("payloads/claims-sensitive.json");
        var token = DoEncrypt(JsonSerializer.Serialize(payload));
        TokenRenderer.RenderJwe(token, $"New {Label} JWE token");
        TokenRenderer.RenderSummary(Label, payload, token);
        AnsiConsole.MarkupLine($"\n[grey]{HintMessage}[/]");
    }

    public void Decrypt()
    {
        var token = io.GetToken(SampleTokenFile);
        ConsoleIO.Attempt(() =>
        {
            TokenRenderer.RenderJwe(token, $"{Label} token to decrypt");
            var payload = ConsoleIO.ParsePayload(DoDecrypt(token));
            TokenRenderer.RenderSuccess(SuccessMessage);
            TokenRenderer.RenderDecodedPayload(payload, "DECRYPTED PAYLOAD");
            TokenRenderer.RenderSummary(Label, payload, token);
        });
    }
}
