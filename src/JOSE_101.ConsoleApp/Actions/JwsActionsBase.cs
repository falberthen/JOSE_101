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
    protected abstract string DoSign(string payloadJson);
    protected abstract string DoVerify(string token);

    public void Create()
    {
        var payload = io.LoadPayload("payloads/claims-basic.json");
        var token = DoSign(JsonSerializer.Serialize(payload));
        TokenRenderer.RenderJws(token, $"New {FamilyName} ({Label}) JWS token");
        TokenRenderer.RenderSummary(Label, payload, token);
        AnsiConsole.MarkupLine($"\n[grey]{HintMessage}[/]");
    }

    public void Verify()
    {
        var token = io.GetToken(SampleTokenFile);
        ConsoleIO.Attempt(() =>
        {
            TokenRenderer.RenderJws(token, $"{FamilyName} ({Label}) token to verify");
            var payload = ConsoleIO.ParsePayload(DoVerify(token));
            TokenRenderer.RenderSuccess(SuccessMessage);
            TokenRenderer.RenderDecodedPayload(payload, "VERIFIED PAYLOAD");
            TokenRenderer.RenderSummary(Label, payload, token);
        });
    }
}
