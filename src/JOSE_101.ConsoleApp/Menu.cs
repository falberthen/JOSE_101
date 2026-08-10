namespace JOSE_101.ConsoleApp;

/// <summary>
/// Menu navigation. 
/// Each algorithm's actual sign/verify/encrypt/decrypt logic lives in its own class under <see cref="Actions"/>.
/// </summary>
public sealed class Menu
{
    private const string SignEncryptChoice = "Sign / Encrypt (create a token)";
    private const string VerifyDecryptChoice = "Verify / Decrypt (validate a token)";
    private const string InspectChoice = "Inspect (no validation)";
    private const string ExitChoice = "Exit";
    private const string BackChoice = "Back";

    private const string HmacLabel = "JWS HMAC (HS256)";
    private const string RsaLabel = "JWS RSA (RS256)";
    private const string EcdsaLabel = "JWS ECDSA (ES256)";
    private const string JweDirectLabel = "JWE Direct (dir + A256GCM)";
    private const string JweRsaOaepLabel = "JWE RSA-OAEP (RSA-OAEP + A256GCM)";

    private readonly ConsoleIO io;
    private readonly HmacActions hmac;
    private readonly RsaActions rsa;
    private readonly EcdsaActions ecdsa;
    private readonly JweDirectActions jweDirect;
    private readonly JweRsaOaepActions jweRsaOaep;
    private readonly NestedActions nested;

    public Menu(string samplesDir, DemoKeys keys)
    {
        io = new ConsoleIO(samplesDir);
        hmac = new HmacActions(keys, io);
        rsa = new RsaActions(keys, io);
        ecdsa = new EcdsaActions(keys, io);
        jweDirect = new JweDirectActions(keys, io);
        jweRsaOaep = new JweRsaOaepActions(keys, io);
        nested = new NestedActions(keys, io);
    }

    public void Run() => RunMainMenu();

    private static void RenderBanner()
    {
        AnsiConsole.Write(new FigletText("JOSE_101").Centered().Color(Color.Blue));
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[grey]JWT - JWA - JWS - JWE playground[/]").Centered());
        AnsiConsole.WriteLine();
    }

    private static void ClearWithBanner()
    {
        AnsiConsole.Clear();
        RenderBanner();
    }

    private static void EndOfAction()
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule().RuleStyle("grey"));
    }

    private void RunMainMenu()
    {
        RenderBanner();
        while (true)
        {
            var action = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("\n[bold]What would you like to do?[/]")
                    .AddChoices(SignEncryptChoice, VerifyDecryptChoice, InspectChoice, ExitChoice));
            ClearWithBanner();

            switch (action)
            {
                case SignEncryptChoice: RunMenu("Sign / Encrypt", CreateActions()); break;
                case VerifyDecryptChoice: RunMenu("Verify / Decrypt", VerifyActions()); break;
                case InspectChoice: RunInspect(); EndOfAction(); break;
                default: return;
            }
        }
    }

    private (string Label, Action Handler)[] CreateActions() =>
    [
        (HmacLabel, hmac.Create),
        (RsaLabel, rsa.Create),
        (EcdsaLabel, ecdsa.Create),
        (JweDirectLabel, jweDirect.Encrypt),
        (JweRsaOaepLabel, jweRsaOaep.Encrypt),
        ("Nested (sign then encrypt)", nested.Create),
    ];

    private (string Label, Action Handler)[] VerifyActions() =>
    [
        (HmacLabel, hmac.Verify),
        (RsaLabel, rsa.Verify),
        (EcdsaLabel, ecdsa.Verify),
        (JweDirectLabel, jweDirect.Decrypt),
        (JweRsaOaepLabel, jweRsaOaep.Decrypt),
        ("Nested (decrypt then verify)", nested.Unwrap),
    ];

    private void RunMenu(string title, (string Label, Action Handler)[] actions)
    {
        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title($"[bold]{title}[/]")
                .AddChoices(actions.Select(a => a.Label).Append(BackChoice)));
        ClearWithBanner();

        if (choice == BackChoice)
            return;

        actions.First(a => a.Label == choice).Handler();
        EndOfAction();
    }

    private void RunInspect()
    {
        var token = io.GetToken("jws-hmac.jwt");
        ConsoleIO.Attempt(() =>
        {
            var result = JoseInspector.Inspect(token);

            TokenRenderer.RenderUnverifiedBanner();
            if (result.TokenType == "JWS")
            {
                TokenRenderer.RenderJws(token, "JWS token (structure only)");
                AnsiConsole.MarkupLine("[grey]3 segments: header.payload.signature. The payload is base64url-encoded but NOT encrypted — anyone can read it.[/]");
            }
            else
            {
                TokenRenderer.RenderJwe(token, "JWE token (structure only)");
                AnsiConsole.MarkupLine("[grey]5 segments: header.encryptedKey.iv.ciphertext.tag. The payload is encrypted and cannot be read without the decryption key.[/]");
            }
        });
    }
}
