using System.Net;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VulnerabilityTracker.Services;

namespace VulnerabilityTracker.Tests;

[TestClass]
public sealed class GitLabSourceReaderTests
{
    [TestMethod]
    public async Task ReadsOnlyCSharpFilesFromNestedProject()
    {
        var handler = new FakeHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/repository/tree")
                ? JsonResponse("""
                    [
                      {"type":"blob","path":"src/Worker.cs"},
                      {"type":"blob","path":"README.md"},
                      {"type":"tree","path":"src"}
                    ]
                    """)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("class Worker { }")
                });
        using var reader = new GitLabSourceReader(handler);

        var files = await reader.ReadAsync("https://gitlab.com/team/subgroup/project.git");

        Assert.AreEqual(1, files.Count);
        Assert.AreEqual(new SourceFile("src/Worker.cs", "class Worker { }"), files[0]);
        Assert.AreEqual(2, handler.Requests.Count);
        StringAssert.Contains(handler.Requests[0].AbsoluteUri, "/projects/team%2Fsubgroup%2Fproject/repository/tree");
        StringAssert.Contains(handler.Requests[1].AbsoluteUri, "/repository/files/src%2FWorker.cs/raw");
    }

    [TestMethod]
    public async Task ReadsNextTreePage()
    {
        var firstPage = JsonSerializer.Serialize(Enumerable.Range(0, 100)
            .Select(index => new { type = "blob", path = $"docs/file{index}.txt" }));
        var handler = new FakeHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/repository/tree"))
            {
                return JsonResponse(request.RequestUri.Query.EndsWith("&page=1", StringComparison.Ordinal)
                    ? firstPage
                    : """[{"type":"blob","path":"Code.cs"}]""");
            }

            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("class Code { }") };
        });
        using var reader = new GitLabSourceReader(handler);

        var files = await reader.ReadAsync("https://gitlab.com/team/project");

        Assert.AreEqual(1, files.Count);
        Assert.AreEqual("Code.cs", files[0].Path);
        Assert.AreEqual(3, handler.Requests.Count);
    }

    [DataTestMethod]
    [DataRow("http://gitlab.com/team/project")]
    [DataRow("https://gitlab.com.evil.test/team/project")]
    [DataRow("https://gitlab.com:444/team/project")]
    [DataRow("https://user:password@gitlab.com/team/project")]
    [DataRow("https://gitlab.com/team/project?token=secret")]
    [DataRow("https://gitlab.com/team/project/-/tree/main")]
    public async Task RejectsUnsupportedRepositoryUrls(string url)
    {
        var handler = new FakeHandler(_ => throw new AssertFailedException("No network request expected."));
        using var reader = new GitLabSourceReader(handler);

        await Assert.ThrowsExceptionAsync<ArgumentException>(() => reader.ReadAsync(url));
        Assert.AreEqual(0, handler.Requests.Count);
    }

    [DataTestMethod]
    [DataRow(HttpStatusCode.Redirect)]
    [DataRow(HttpStatusCode.NotFound)]
    public async Task DoesNotTreatGitLabErrorsAsEmptyResults(HttpStatusCode status)
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(status)
        {
            Headers = { Location = new Uri("https://example.com/other") }
        });
        using var reader = new GitLabSourceReader(handler);

        await Assert.ThrowsExceptionAsync<HttpRequestException>(
            () => reader.ReadAsync("https://gitlab.com/team/project"));
        Assert.AreEqual(1, handler.Requests.Count);
    }

    [TestMethod]
    public async Task RejectsFileAboveSizeLimit()
    {
        var handler = new FakeHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/repository/tree")
                ? JsonResponse("""[{"type":"blob","path":"Large.cs"}]""")
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(new string('x', 100_001))
                });
        using var reader = new GitLabSourceReader(handler);

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => reader.ReadAsync("https://gitlab.com/team/project"));
    }

    [TestMethod]
    public async Task RejectsTooManyCSharpFiles()
    {
        var tree = JsonSerializer.Serialize(Enumerable.Range(0, 31)
            .Select(index => new { type = "blob", path = $"File{index}.cs" }));
        var handler = new FakeHandler(_ => JsonResponse(tree));
        using var reader = new GitLabSourceReader(handler);

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => reader.ReadAsync("https://gitlab.com/team/project"));
        Assert.AreEqual(1, handler.Requests.Count);
    }

    [TestMethod]
    public async Task RejectsFilesAboveCombinedSizeLimit()
    {
        var tree = JsonSerializer.Serialize(Enumerable.Range(0, 11)
            .Select(index => new { type = "blob", path = $"File{index}.cs" }));
        var handler = new FakeHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/repository/tree")
                ? JsonResponse(tree)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(new string('x', 100_000))
                });
        using var reader = new GitLabSourceReader(handler);

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => reader.ReadAsync("https://gitlab.com/team/project"));
    }

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json)
    };

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(respond(request));
        }
    }
}
