namespace VulnerabilityTracker.Contracts;

public sealed record CancelScanResponse(Guid Id, bool Canceled, DateTimeOffset AttemptedAt);
