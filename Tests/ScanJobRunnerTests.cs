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

    [TestMethod]
    public async Task StartsQueuedScanWhenWorkerBecomesAvailable()
    {
        var firstStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new FakeHandler(async (request, cancellationToken) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/repository/tree"))
            {
                if (request.RequestUri.AbsoluteUri.Contains("team%2Ffirst", StringComparison.Ordinal))
                {
                    firstStarted.TrySetResult(true);
                    await releaseFirst.Task.WaitAsync(cancellationToken);
                }
                else
                {
                    secondStarted.TrySetResult(true);
                }
            }

            return Ok("[]");
        });
        using var reader = new GitLabSourceReader(handler);
        var store = new ScanJobStore();
        using var runner = new ScanJobRunner(
            new RepositoryScanner(reader, new CSharpSourceScanner()),
            store, NullLogger<ScanJobRunner>.Instance, maxParallelScans: 1);
        await runner.StartAsync(CancellationToken.None);

        try
        {
            var first = runner.StartScan("https://gitlab.com/team/first");
            await firstStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var second = runner.StartScan("https://gitlab.com/team/second");

            Assert.IsTrue(store.TryGet(second, out var queued));
            Assert.AreEqual(ScanStatus.Queued, queued!.Status);
            Assert.IsFalse(secondStarted.Task.IsCompleted);

            releaseFirst.SetResult(true);
            await WaitForStatusAsync(store, first, ScanStatus.Completed);
            await secondStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var completed = await WaitForStatusAsync(store, second, ScanStatus.Completed);
            Assert.IsTrue(completed.StatusChangedAt >= queued.StatusChangedAt);
        }
        finally
        {
            releaseFirst.TrySetResult(true);
            await runner.StopAsync(CancellationToken.None);
        }
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
