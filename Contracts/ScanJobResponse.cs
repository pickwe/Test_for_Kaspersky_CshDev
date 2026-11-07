using System.Text.Json.Serialization;

namespace VulnerabilityTracker.Contracts;

public sealed record ScanFindingResponse(
    string RuleId,
    string Description,
    string FilePath,
    int LineNumber);

public sealed record ScanJobResponse(
    Guid Id,
    string Status,
    DateTimeOffset StatusChangedAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<ScanFindingResponse>? Result,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Error);
