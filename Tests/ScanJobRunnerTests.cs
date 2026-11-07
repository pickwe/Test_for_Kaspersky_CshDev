using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VulnerabilityTracker.Services;

namespace VulnerabilityTracker.Tests;

[TestClass]
public sealed class ScanJobRunnerTests
{
    [TestMethod]
    public async Task ReturnsIdBeforeScanFinishesAndSavesResult()
    {
        var requestStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseTree = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new FakeHandler((request, cancellationToken) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/repository/tree"))
            {
                requestStarted.TrySetResult(true);
                return releaseTree.Task.WaitAsync(cancellationToken);
            }

            return Task.FromResult(Ok("new BinaryFormatter().Deserialize(stream);"));
        });
        using var reader = new GitLabSourceReader(handler);
        var store = new ScanJobStore();
        using var runner = new ScanJobRunner(
            new RepositoryScanner(reader, new CSharpSourceScanner()),
            store, NullLogger<ScanJobRunner>.Instance);
        await runner.StartAsync(CancellationToken.None);

        var id = runner.StartScan("https://gitlab.com/team/project");
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreNotEqual(Guid.Empty, id);
        Assert.IsTrue(store.TryGet(id, out var running));
        Assert.AreEqual(ScanStatus.Running, running!.Status);
        Assert.IsNull(running.Result);

        releaseTree.SetResult(Ok("""[{"type":"blob","path":"Unsafe.cs"}]"""));
        var completed = await WaitForStatusAsync(store, id, ScanStatus.Completed);

        Assert.AreEqual(1, completed.Result!.Count);
        Assert.AreEqual("SERIAL001", completed.Result[0].RuleId);
        Assert.IsNull(completed.Error);
        Assert.IsTrue(completed.StatusChangedAt >= running.StatusChangedAt);
        await runner.StopAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task SavesSafeErrorWhenGitLabFails()
    {
        var handler = new FakeHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var reader = new GitLabSourceReader(handler);
        var store = new ScanJobStore();
        using var runner = new ScanJobRunner(
            new RepositoryScanner(reader, new CSharpSourceScanner()),
            store, NullLogger<ScanJobRunner>.Instance);
        await runner.StartAsync(CancellationToken.None);

        var id = runner.StartScan("https://gitlab.com/team/missing");
        var failed = await WaitForStatusAsync(store, id, ScanStatus.Failed);

        Assert.AreEqual("Scan failed.", failed.Error);
        Assert.IsNull(failed.Result);
        await runner.StopAsync(CancellationToken.None);
    }

    private static async Task<ScanJob> WaitForStatusAsync(
        ScanJobStore store, Guid id, ScanStatus expected)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (store.TryGet(id, out var job) && job!.Status == expected)
            {
                return job;
            }

            await Task.Delay(20);
        }

        throw new AssertFailedException($"Scan {id} did not reach {expected}.");
    }

    private static HttpResponseMessage Ok(string content) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(content)
    };

    private sealed class FakeHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(request, cancellationToken);
    }
}
