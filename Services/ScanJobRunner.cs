using System.Threading.Channels;

namespace VulnerabilityTracker.Services;

public sealed class ScanJobRunner(
    RepositoryScanner scanner,
    ScanJobStore store,
    ILogger<ScanJobRunner> logger,
    int maxParallelScans = 2) : IHostedService, IDisposable
{
    // Each worker takes one scan at a time from this shared queue.
    private readonly Channel<(Guid Id, string RepositoryUrl)> _queue =
        Channel.CreateUnbounded<(Guid, string)>();
    private readonly CancellationTokenSource _stopping = new();
    private Task[] _workers = [];

    public Guid StartScan(string repositoryUrl)
    {
        if (_stopping.IsCancellationRequested)
        {
            throw new InvalidOperationException("The scan service is stopping.");
        }

        var job = store.Create();
        if (!_queue.Writer.TryWrite((job.Id, repositoryUrl)))
        {
            store.Fail(job.Id, "Scan could not be queued.");
            throw new InvalidOperationException("The scan queue is closed.");
        }

        return job.Id;
    }

    private async Task RunWorkerAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var (id, repositoryUrl) in _queue.Reader.ReadAllAsync(cancellationToken))
            {
                if (!store.Start(id))
                {
                    continue;
                }

                await ProcessScanAsync(id, repositoryUrl, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
        {
            // Stopping the service also stops workers waiting for another scan.
        }
    }

    private async Task ProcessScanAsync(Guid id, string repositoryUrl, CancellationToken cancellationToken)
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
            store.Fail(id, "Scan failed.");
            logger.LogError(exception, "Scan {ScanId} failed", id);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (maxParallelScans < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxParallelScans), "Must be at least 1.");
        }

        _workers = new Task[maxParallelScans];
        for (var index = 0; index < _workers.Length; index++)
        {
            _workers[index] = Task.Run(() => RunWorkerAsync(_stopping.Token));
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _queue.Writer.TryComplete();
        _stopping.Cancel();
        await Task.WhenAll(_workers).WaitAsync(cancellationToken);
    }

    public void Dispose() => _stopping.Dispose();
}
