namespace JOSE_101.ConsoleApp.Actions;

/// <summary>Template for JWS create/verify — shared prompt/render orchestration. Each algorithm subclass supplies only its key-specific sign/verify calls and didactic labels (Open/Closed: a new JWS algorithm is a new subclass, no changes here).</summary>
public abstract class JwsActionsBase
{
    protected readonly ConsoleIO io;

    protected JwsActionsBase(ConsoleIO io)
    {
        this.io = io;
    }

    protected abstract string FamilyName { get; }
    protected abstract string Label { get; }
    protected abstract string SampleTokenFile { get; }
    protected abstract string HintMessage { get; }
    protected abstract string SuccessMessage { get; }
    protected abstract string KeyPromptHint { get; }
    protected abstract string DoSign(string payloadJson);
    protected abstract string DoVerify(string token);
    protected abstract string DoVerifyWithKey(string token, string keyInput);

    public void Create()
    {
        var payload = io.LoadPayload("payloads/claims-basic.json");
        var token = DoSign(JsonSerializer.Serialize(payload));
        ResultRenderer.RenderJws(token, $"New {FamilyName} ({Label}) JWS token");
        ResultRenderer.RenderSummary(Label, payload, token);
        AnsiConsole.MarkupLine($"\n[grey]{HintMessage}[/]");
    }

    public void Verify()
    {
        var (token, isBundled) = io.GetTokenWithSource(SampleTokenFile);

        ConsoleIO.Attempt(() =>
        {
            ResultRenderer.RenderJws(token, $"{FamilyName} ({Label}) token to verify");

            string payloadJson;
            if (isBundled)
            {
                payloadJson = DoVerify(token);
            }
            else
            {
                Console.WriteLine();
                var keyInput = ConsoleIO.PromptMultiline($"Paste the {KeyPromptHint}:");
                payloadJson = DoVerifyWithKey(token, keyInput);
            }

            var payload = ConsoleIO.ParsePayload(payloadJson);
            ResultRenderer.RenderSuccess(SuccessMessage);
            ResultRenderer.RenderSummaryWithPayload(Label, payload, token, "VERIFIED PAYLOAD");
        });
    }
}
