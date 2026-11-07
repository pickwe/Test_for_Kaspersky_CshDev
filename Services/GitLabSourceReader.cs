using System.Text;
using System.Text.Json;

namespace VulnerabilityTracker.Services;

public sealed record SourceFile(string Path, string Content);

public sealed class GitLabSourceReader : IDisposable
{
    private const int PageSize = 100;
    private const int MaxPages = 10;
    private const int MaxFiles = 30;
    private const int MaxTreeBytes = 256_000;
    private const int MaxFileBytes = 100_000;
    private const int MaxTotalBytes = 1_000_000;

    private readonly HttpClient _client;

    public GitLabSourceReader(HttpMessageHandler? handler = null)
    {
        _client = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false });
    }

    public async Task<IReadOnlyList<SourceFile>> ReadAsync(
        string repositoryUrl, CancellationToken cancellationToken = default)
    {
        var projectPath = GetProjectPath(repositoryUrl);
        var projectApi = $"https://gitlab.com/api/v4/projects/{Uri.EscapeDataString(projectPath)}";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));

        var paths = new List<string>();
        for (var page = 1; page <= MaxPages; page++)
        {
            var url = $"{projectApi}/repository/tree?recursive=true&per_page={PageSize}&page={page}";
            var bytes = await GetBytesAsync(url, MaxTreeBytes, deadline.Token);
            using var document = JsonDocument.Parse(bytes);
            var entries = document.RootElement.EnumerateArray();
            var entryCount = 0;

            foreach (var entry in entries)
            {
                entryCount++;
                if (entry.GetProperty("type").GetString() != "blob")
                {
                    continue;
                }

                var path = entry.GetProperty("path").GetString();
                if (path is null || !path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                paths.Add(path);
                if (paths.Count > MaxFiles)
                {
                    throw new InvalidOperationException("Repository has too many C# files to scan.");
                }
            }

            if (entryCount < PageSize)
            {
                break;
            }

            if (page == MaxPages)
            {
                throw new InvalidOperationException("Repository tree is too large to scan.");
            }
        }

        var files = new List<SourceFile>();
        var totalBytes = 0;
        foreach (var path in paths)
        {
            var url = $"{projectApi}/repository/files/{Uri.EscapeDataString(path)}/raw";
            var bytes = await GetBytesAsync(url, Math.Min(MaxFileBytes, MaxTotalBytes - totalBytes), deadline.Token);
            totalBytes += bytes.Length;
            files.Add(new SourceFile(path, Encoding.UTF8.GetString(bytes)));
        }

        return files;
    }

    private async Task<byte[]> GetBytesAsync(string url, int maxBytes, CancellationToken cancellationToken)
    {
        using var response = await _client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new HttpRequestException("GitLab returned a redirect.");
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                throw new InvalidOperationException("GitLab response exceeds the scan size limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static string GetProjectPath(string repositoryUrl)
    {
        if (!Uri.TryCreate(repositoryUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.Equals(uri.Host, "gitlab.com", StringComparison.OrdinalIgnoreCase) ||
            !uri.IsDefaultPort ||
            uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)
        {
            throw new ArgumentException("Use an HTTPS URL of a public gitlab.com project.", nameof(repositoryUrl));
        }

        var segments = Uri.UnescapeDataString(uri.AbsolutePath).Trim('/').Split('/');
        if (segments.Length < 2 || segments.Any(segment =>
            string.IsNullOrWhiteSpace(segment) || segment is "." or ".." or "-"))
        {
            throw new ArgumentException("The URL must contain a GitLab group and project.", nameof(repositoryUrl));
        }

        if (segments[^1].EndsWith(".git", StringComparison.OrdinalIgnoreCase))
        {
            segments[^1] = segments[^1][..^4];
        }

        if (segments[^1].Length == 0)
        {
            throw new ArgumentException("The URL must contain a project name.", nameof(repositoryUrl));
        }

        return string.Join('/', segments);
    }

    public void Dispose() => _client.Dispose();
}
