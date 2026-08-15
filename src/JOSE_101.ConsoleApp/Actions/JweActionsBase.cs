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
    protected abstract string KeyPromptHint { get; }
    protected abstract string DoEncrypt(string payloadJson);
    protected abstract string DoDecrypt(string token);
    protected abstract string DoDecryptWithKey(string token, string keyInput);

    public void Encrypt()
    {
        var payload = io.LoadPayload("payloads/claims-sensitive.json");
        var token = DoEncrypt(JsonSerializer.Serialize(payload));
        ResultRenderer.RenderJwe(token, $"New {Label} JWE token");
        ResultRenderer.RenderSummary(Label, payload, token);
        AnsiConsole.MarkupLine($"\n[grey]{HintMessage}[/]");
    }

    public void Decrypt()
    {
        var (token, isBundled) = io.GetTokenWithSource(SampleTokenFile);

        ConsoleIO.Attempt(() =>
        {
            ResultRenderer.RenderJwe(token, $"{Label} token to decrypt");

            string payloadJson;
            if (isBundled)
            {
                payloadJson = DoDecrypt(token);
            }
            else
            {
                Console.WriteLine();
                var keyInput = ConsoleIO.PromptMultiline($"Paste the {KeyPromptHint}:");
                payloadJson = DoDecryptWithKey(token, keyInput);
            }

            var payload = ConsoleIO.ParsePayload(payloadJson);
            ResultRenderer.RenderSuccess(SuccessMessage);
            ResultRenderer.RenderSummaryWithPayload(Label, payload, token, "DECRYPTED PAYLOAD");
        });
    }
}
