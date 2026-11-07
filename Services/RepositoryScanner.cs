namespace VulnerabilityTracker.Services;

public sealed class RepositoryScanner(
    GitLabSourceReader sourceReader,
    CSharpSourceScanner sourceScanner)
{
    public async Task<IReadOnlyList<ScanFinding>> ScanAsync(
        string repositoryUrl, CancellationToken cancellationToken = default)
    {
        var files = await sourceReader.ReadAsync(repositoryUrl, cancellationToken);
        var findings = new List<ScanFinding>();

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            findings.AddRange(sourceScanner.Scan(file.Path, file.Content, cancellationToken));
        }

        return findings;
    }
}
