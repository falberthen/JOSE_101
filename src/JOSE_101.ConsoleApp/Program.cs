var repoRoot = KeyStore.FindRepoRoot(AppContext.BaseDirectory);
var samplesDir = Path.Combine(repoRoot, "samples");
var keys = KeyStore.Load(Path.Combine(repoRoot, "keys"));

new Menu(samplesDir, keys).Run();
