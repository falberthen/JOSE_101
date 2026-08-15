namespace JOSE_101.ConsoleApp;

/// <summary>
/// Colored console rendering of JOSE tokens segment-by-segment breakdown, summary panels, and step-by-step animation for nested unwrap.
/// </summary>
public static class TokenRenderer
{
    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    private static readonly (string Tag, Color Value) HeaderColor = ("orange3", Color.Orange3);
    private static readonly (string Tag, Color Value) PayloadColor = ("purple_2", Color.Purple_2);
    private static readonly (string Tag, Color Value) SignatureColor = ("deepskyblue1", Color.DeepSkyBlue1);
    private static readonly (string Tag, Color Value) EncryptedColor = ("lightyellow3", Color.LightYellow3);

    /// <summary>
    /// Renders a JWS token's 3 segments side by side: header, payload, signature. 
    /// Narrow terminals wrap the columns automatically.
    /// </summary>
    public static void RenderJws(string token, string title)
    {
        var parts = SplitSegments(token);
        EnsureSegmentCount(parts, 3, "JWS");
        RenderTitle(title);
        RenderComposedToken(parts, HeaderColor.Tag, PayloadColor.Tag, SignatureColor.Tag);
        WriteSegmentRow(
            38,
            Segment($"[{HeaderColor.Tag}]HEADER[/]", PrettyDecode(parts[0]), HeaderColor.Value, width: 38),
            Segment($"[{PayloadColor.Tag}]PAYLOAD[/]", PrettyDecode(parts[1]), PayloadColor.Value, width: 38),
            Segment($"[{SignatureColor.Tag}]SIGNATURE[/]", parts[2], SignatureColor.Value, width: 38));
    }

    /// <summary>
    /// Renders a JWE token's 5 segments side by side: header (only content is encrypted) and encrypted-key/IV/ciphertext/tag. 
    /// Narrow terminals wrap the columns automatically.</summary>
    public static void RenderJwe(string token, string title)
    {
        var parts = SplitSegments(token);
        EnsureSegmentCount(parts, 5, "JWE");
        RenderTitle(title);
        RenderComposedToken(parts, HeaderColor.Tag, EncryptedColor.Tag, EncryptedColor.Tag, EncryptedColor.Tag, EncryptedColor.Tag);
        WriteSegmentRow(
            22,
            Segment($"[{HeaderColor.Tag}]HEADER[/]", PrettyDecode(parts[0]), HeaderColor.Value, width: 22),
            Segment($"[{EncryptedColor.Tag}]ENCRYPTED KEY[/]", parts[1].Length == 0
                ? "(empty — \"dir\" has no key wrapping)"
                : Mask(parts[1]), EncryptedColor.Value, width: 22),
            Segment($"[{EncryptedColor.Tag}]IV[/]", Mask(parts[2]), EncryptedColor.Value, width: 22),
            Segment($"[{EncryptedColor.Tag}]CIPHERTEXT[/]", Mask(parts[3]), EncryptedColor.Value, width: 22),
            Segment($"[{EncryptedColor.Tag}]TAG[/]", Mask(parts[4]), EncryptedColor.Value, width: 22));
    }

    /// <summary>
    /// Centered bold title, followed by a blank line shared by every token-rendering entry point so titles line up the same way everywhere.
    /// </summary>
    private static void RenderTitle(string title)
    {
        AnsiConsole.Write(Align.Center(new Markup($"[bold]{Markup.Escape(title)}[/]")));
        AnsiConsole.WriteLine();
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Prints the raw compact-serialization token as one line, each segment colored to match its panel below and dots 
    /// makes the header.payload.signature (or 5-part JWE) composition visible at a glance before it's broken apart.
    /// </summary>
    private static void RenderComposedToken(string[] parts, params string[] colorTags)
    {
        var composed = string.Join("[grey].[/]", parts.Select((part, i) => $"[{colorTags[i]}]{Markup.Escape(part)}[/]"));
        AnsiConsole.Write(new Markup(composed));
        AnsiConsole.WriteLine();
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Green panel for a payload that has just been decrypted or signature-verified.
    /// </summary>
    public static void RenderDecodedPayload(Dictionary<string, object> payload, string label = "DECRYPTED / VERIFIED PAYLOAD")
    {
        AnsiConsole.Write(Segment($"[green]{Markup.Escape(label)}[/]", JsonSerializer.Serialize(payload, PrettyJson), Color.Green));
    }

    /// <summary>
    /// Always-shown summary: algorithm(s), the raw claims, and the token's wire size.
    ///</summary>
    public static void RenderSummary(string algorithms, Dictionary<string, object> payload, string token)
    {
        var sizeBytes = Encoding.UTF8.GetByteCount(token);
        var content = new Rows(
            new Markup($"[bold]Algorithm(s):[/] [{HeaderColor.Tag}]{Markup.Escape(algorithms)}[/]"),
            new Markup($"[bold]Token size:[/] {sizeBytes} bytes"),
            new Markup($"[bold {PayloadColor.Tag}]Payload / claims:[/]"),
            new Text(JsonSerializer.Serialize(payload, PrettyJson), new Style(foreground: PayloadColor.Value)));

        AnsiConsole.Write(new Panel(content).Header("[bold white]SUMMARY[/]").BorderColor(Color.White));
    }

    public static void RenderUnverifiedBanner()
        => AnsiConsole.Write(new Panel(new Markup("[bold red]! UNVERIFIED ![/] — header/payload decoded below, but NO signature check and NO decryption were performed. Never use this for authorization."))
            .BorderColor(Color.Red));

    /// <summary>
    /// One step of an animated multi-step operation.
    /// </summary>
    public static void RenderStep(string message)
    {
        AnsiConsole.MarkupLine($"[yellow]-> {Markup.Escape(message)}[/]");
        Thread.Sleep(500);
    }

    public static void RenderSuccess(string message) =>
        AnsiConsole.MarkupLine($"[bold green]OK {Markup.Escape(message)}[/]");

    public static void RenderError(string message) => 
        AnsiConsole.Write(new Panel(new Text(message, new Style(foreground: Color.Red)))
            .Header("[bold red]ERROR[/]")
            .BorderColor(Color.Red));

    /// <summary>
    /// Splits a compact-serialization token into its dot-separated segments the single place every renderer gets its parts from.
    /// </summary>
    private static string[] SplitSegments(string token) => 
        token.Split('.');

    /// <summary>
    /// Guards against a malformed/pasted-wrong-type token before any segment indexing happens 
    /// turns a raw <see cref="IndexOutOfRangeException"/> into a message that actually explains what's wrong.
    /// </summary>
    private static void EnsureSegmentCount(string[] parts, int expected, string tokenType)
    {
        if (parts.Length != expected)
            throw new FormatException($"Not a valid {tokenType} token: expected {expected} dot-separated segments, got {parts.Length}.");
    }

    /// <summary>
    /// A colored, vertically-centered separator shown between segment panels so the row visually reads as one dot-joined token, 
    /// not unrelated boxes. A fixed height is required for the vertical centering to have anything to center within
    /// without it, <see cref="Align"/> just renders at the top of the row.
    /// </summary>
    private static IRenderable Dot()
    {
        var align = Align.Center(new Markup("[bold white].[/]"), VerticalAlignment.Middle);
        align.Height = 5;
        return align;
    }

    /// <summary>
    /// Lays out segment panels tightly side by side (a fixed-width <see cref="Grid"/>, 
    /// not the auto-expanding <see cref="Columns"/>) with a narrow dot separator between each 
    /// keeps panels close together regardless of terminal width.
    /// </summary>
    private static void WriteSegmentRow(int panelWidth, params IRenderable[] panels)
    {
        var grid = new Grid();
        for (var i = 0; i < panels.Length; i++)
        {
            grid.AddColumn(new GridColumn().Width(panelWidth).PadLeft(0).PadRight(0));
            if (i < panels.Length - 1)
                grid.AddColumn(new GridColumn().Width(3).PadLeft(0).PadRight(0));
        }

        var row = new List<IRenderable>();
        for (var i = 0; i < panels.Length; i++)
        {
            row.Add(panels[i]);
            if (i < panels.Length - 1)
                row.Add(Dot());
        }

        grid.AddRow([.. row]);
        AnsiConsole.Write(grid);
    }

    private static Panel Segment(string headerMarkup, string content, Color color, int? width = null)
    {
        var panel = new Panel(new Text(content, new Style(foreground: color))).Header(headerMarkup).BorderColor(color);
        if (width is not null)
        {
            panel.Width = width;
        }

        return panel;
    }

    /// <summary>
    /// Base64url-decodes a JOSE header/payload segment and pretty-prints it as JSON; falls back to the raw segment if it isn't JSON.
    /// </summary>
    private static string PrettyDecode(string base64UrlSegment)
    {
        try
        {
            var json = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(base64UrlSegment));
            return JsonSerializer.Serialize(JsonSerializer.Deserialize<Dictionary<string, object>>(json), PrettyJson);
        }
        catch
        {
            return base64UrlSegment;
        }
    }

    /// <summary>
    /// Truncates a long opaque (encrypted) segment to a preview short enough for a narrow side-by-side column, keeping the exact length visible.
    /// </summary>
    private static string Mask(string segment)
    {
        const int keep = 6;
        if (segment.Length <= keep * 2)
        {
            return $"{segment}\n({segment.Length} chars)";
        }

        return $"{segment[..keep]}...{segment[^keep..]}\n({segment.Length} chars,\nopaque)";
    }
}
