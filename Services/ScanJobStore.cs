using System.Collections.Concurrent;

namespace VulnerabilityTracker.Services;

public enum ScanStatus { Running, Completed, Failed }

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
        var job = new ScanJob(Guid.NewGuid(), ScanStatus.Running, DateTimeOffset.UtcNow, null, null);
        _jobs[job.Id] = job;
        return job;
    }

    public bool TryGet(Guid id, out ScanJob? job) => _jobs.TryGetValue(id, out job);

    public bool Complete(Guid id, IReadOnlyList<ScanFinding> findings) =>
        Update(id, ScanStatus.Completed, findings.ToArray(), null);

    public bool Fail(Guid id, string error) => Update(id, ScanStatus.Failed, null, error);

    private bool Update(Guid id, ScanStatus status, IReadOnlyList<ScanFinding>? result, string? error)
    {
        while (_jobs.TryGetValue(id, out var current))
        {
            if (current.Status != ScanStatus.Running)
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

            if (_jobs.TryUpdate(id, updated, current))
            {
                return true;
            }
        }

        return false;
    }
}
