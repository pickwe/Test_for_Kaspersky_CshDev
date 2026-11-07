using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VulnerabilityTracker.Services;

namespace VulnerabilityTracker.Tests;

[TestClass]
public sealed class RepositoryScannerTests
{
    [TestMethod]
    public async Task ReturnsFindingsWithPathsFromRepositoryFiles()
    {
        var handler = new FakeHandler(request =>
        {
            var url = request.RequestUri!.AbsoluteUri;
            if (url.Contains("/repository/tree", StringComparison.Ordinal))
            {
                return Ok("""
                    [
                      {"type":"blob","path":"src/Network.cs"},
                      {"type":"blob","path":"src/Data.cs"}
                    ]
                    """);
            }

            return url.Contains("Network.cs", StringComparison.Ordinal)
                ? Ok("handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;")
                : Ok("var command = new SqlCommand($\"SELECT * FROM Users WHERE Id = {userId}\", connection);");
        });
        using var reader = new GitLabSourceReader(handler);
        var scanner = new RepositoryScanner(reader, new CSharpSourceScanner());

        var findings = await scanner.ScanAsync("https://gitlab.com/team/project");

        Assert.AreEqual(2, findings.Count);
        Assert.AreEqual(new ScanFinding(
            "TLS001", "Certificate validation always returns true.", "src/Network.cs", 1), findings[0]);
        Assert.AreEqual(new ScanFinding(
            "SQL001", "A SQL query is built from dynamic text; use parameters instead.",
            "src/Data.cs", 1), findings[1]);
    }

    private static HttpResponseMessage Ok(string content) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(content)
    };

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
