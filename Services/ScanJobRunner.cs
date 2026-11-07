namespace VulnerabilityTracker.Services;

public sealed class ScanJobRunner(
    RepositoryScanner scanner,
    ScanJobStore store,
    ILogger<ScanJobRunner> logger) : IHostedService, IDisposable
{
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Task> _tasks = [];

    public Guid StartScan(string repositoryUrl)
    {
        var job = store.Create();
        lock (_tasks)
        {
            _tasks.RemoveAll(task => task.IsCompleted);
            _tasks.Add(Task.Run(() => RunAsync(job.Id, repositoryUrl, _stopping.Token)));
        }

        return job.Id;
    }

    private async Task RunAsync(Guid id, string repositoryUrl, CancellationToken cancellationToken)
    {
        try
        {
            var findings = await scanner.ScanAsync(repositoryUrl, cancellationToken);
            store.Complete(id, findings);
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
        {
            store.Fail(id, "Scan stopped.");
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scan {ScanId} failed", id);
            store.Fail(id, "Scan failed.");
        }
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping.Cancel();
        Task[] tasks;
        lock (_tasks)
        {
            tasks = _tasks.ToArray();
        }

        await Task.WhenAll(tasks).WaitAsync(cancellationToken);
    }

    public void Dispose() => _stopping.Dispose();
}
