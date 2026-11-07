using System.Collections.Concurrent;

namespace VulnerabilityTracker.Services;

public enum ScanStatus { Queued, Running, Completed, Failed, Canceled }

public sealed record ScanJob(
    Guid Id,
    ScanStatus Status,
    DateTimeOffset StatusChangedAt,
    IReadOnlyList<ScanFinding>? Result,
    string? Error);

public sealed class ScanJobStore
{
    private readonly ConcurrentDictionary<Guid, ScanJob> _jobs = new();

    public ScanJob Create()
    {
        var job = new ScanJob(Guid.NewGuid(), ScanStatus.Queued, DateTimeOffset.UtcNow, null, null);
        _jobs[job.Id] = job;
        return job;
    }

    public bool TryGet(Guid id, out ScanJob? job) => _jobs.TryGetValue(id, out job);

    public bool Start(Guid id) => Update(id, [ScanStatus.Queued], ScanStatus.Running, null, null);

    public bool Complete(Guid id, IReadOnlyList<ScanFinding> findings) =>
        Update(id, [ScanStatus.Running], ScanStatus.Completed, findings.ToArray(), null);

    public bool Fail(Guid id, string error) =>
        Update(id, [ScanStatus.Queued, ScanStatus.Running], ScanStatus.Failed, null, error);

    public bool Cancel(Guid id) =>
        Update(id, [ScanStatus.Queued, ScanStatus.Running], ScanStatus.Canceled, null, null);

    private bool Update(Guid id, ScanStatus[] allowedStatuses, ScanStatus status,
        IReadOnlyList<ScanFinding>? result, string? error)
    {
        while (_jobs.TryGetValue(id, out var current))
        {
            if (!allowedStatuses.Contains(current.Status))
            {
                return false;
            }

            var updated = current with
            {
                Status = status,
                StatusChangedAt = DateTimeOffset.UtcNow,
                Result = result,
                Error = error
            };

            // Another request may change this job first; retry with its latest state.
            if (_jobs.TryUpdate(id, updated, current))
            {
                return true;
            }
        }

        return false;
    }
}
