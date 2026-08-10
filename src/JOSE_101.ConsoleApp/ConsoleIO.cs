namespace JOSE_101.ConsoleApp;

/// <summary>
/// Console prompting/IO used by the menu — asking for an algorithm, loading a payload file, getting a token, and running an operation with error display. 
/// No menu-navigation or JOSE logic lives here.
/// </summary>
public sealed class ConsoleIO
{
    private readonly string samplesDir;

    public ConsoleIO(string samplesDir)
    {
        this.samplesDir = samplesDir;
    }

    public static string AskAlgorithm(string title, params string[] options) =>
        AnsiConsole.Prompt(new SelectionPrompt<string>()
            .Title(title)
            .AddChoices(options));

    public Dictionary<string, object> LoadPayload(string defaultRelativePath)
    {
        var relativePath = AnsiConsole.Prompt(new TextPrompt<string>("Payload file under samples/:")
            .DefaultValue(defaultRelativePath));
        var json = File.ReadAllText(Path.Combine(samplesDir, relativePath));

        AnsiConsole.MarkupLine($"\n[grey]--- payload read from samples/{Markup.Escape(relativePath)} (edit this file to try your own claims) ---[/]");
        AnsiConsole.WriteLine(json.Trim());
        AnsiConsole.WriteLine();

        return JsonSerializer.Deserialize<Dictionary<string, object>>(json)!;
    }

    public string GetToken(string defaultSampleFileName)
    {
        var input = AnsiConsole.Prompt(
            new TextPrompt<string>($"Paste a token, or leave blank to use the bundled sample ([grey]{defaultSampleFileName}[/]):")
                .AllowEmpty());
        var token = new StringBuilder(input);

        // Drain whatever is still waiting in the input buffer and stitch it back into a single token:
        // a JOSE compact token never legitimately contains whitespace, so every line break here is a paste artifact, not real content.
        while (!Console.IsInputRedirected && Console.KeyAvailable)
        {
            token.Append(Console.ReadLine());
        }

        AnsiConsole.WriteLine();

        if (!string.IsNullOrWhiteSpace(token.ToString()))
            return token.ToString().Trim();

        return File.ReadAllText(Path.Combine(samplesDir, defaultSampleFileName)).Trim();
    }

    public static Dictionary<string, object> ParsePayload(string payloadJson) => 
        JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson)!;

    public static void Attempt(Action operation)
    {
        try
        {
            operation();
        }
        catch (Exception ex)
        {
            TokenRenderer.RenderError(ex.Message);
            AnsiConsole.MarkupLine("\n[grey](press Enter to continue)[/]");
            Console.ReadLine();
        }
    }
}
