using System.Diagnostics;
using VulnerabilityTracker.Contracts;
using VulnerabilityTracker.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddProblemDetails();

builder.Services.AddSingleton<VulnerabilityStore>();
builder.Services.AddSingleton(_ => new GitLabSourceReader());
builder.Services.AddSingleton<CSharpSourceScanner>();
builder.Services.AddSingleton<RepositoryScanner>();
builder.Services.AddSingleton<ScanJobStore>();
builder.Services.AddSingleton(provider => new ScanJobRunner(
    provider.GetRequiredService<RepositoryScanner>(),
    provider.GetRequiredService<ScanJobStore>(),
    provider.GetRequiredService<ILogger<ScanJobRunner>>(),
    builder.Configuration.GetValue("Scanning:MaxParallelScans", 2)));
builder.Services.AddHostedService(provider => provider.GetRequiredService<ScanJobRunner>());

var app = builder.Build();

app.Use(async (context, next) =>
{
    var started = Stopwatch.GetTimestamp();
    var statusCode = StatusCodes.Status500InternalServerError;

    try
    {
        await next(context);
        statusCode = context.Response.StatusCode;
    }
    finally
    {
        app.Logger.LogInformation("{Method} {Path} -> {StatusCode} in {ElapsedMs:F1} ms",
            context.Request.Method,
            context.Request.Path,
            statusCode,
            Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    }
});
app.UseExceptionHandler();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/vulnerabilities", (CreateVulnerabilityRequest request, VulnerabilityStore store) =>
{
    if (!store.TryAdd(request, out var vulnerability, out var error))
    {
        return Results.BadRequest(new { error });
    }

    return Results.Created($"/api/vulnerabilities/{vulnerability!.Id}", vulnerability);
});

app.MapGet("/api/vulnerabilities/{id}", (string id, VulnerabilityStore store) =>
{
    if (!Guid.TryParse(id, out var vulnerabilityId))
    {
        return Results.BadRequest(new { error = "Id must be a valid GUID." });
    }

    return store.TryGet(vulnerabilityId, out var vulnerability)
        ? Results.Ok(vulnerability)
        : Results.NotFound();
});

app.MapPost("/api/scans", (CreateScanRequest? request, ScanJobRunner runner) =>
{
    if (!GitLabSourceReader.IsSupportedUrl(request?.RepositoryUrl))
    {
        return Results.BadRequest(new { error = "Use an HTTPS URL of a public gitlab.com project." });
    }

    var id = runner.StartScan(request!.RepositoryUrl);
    return Results.Accepted($"/api/scans/{id}", new CreateScanResponse(id));
});

app.MapGet("/api/scans/{id}", (string id, ScanJobStore store) =>
{
    if (!Guid.TryParse(id, out var scanId))
    {
        return Results.BadRequest(new { error = "Id must be a valid GUID." });
    }

    if (!store.TryGet(scanId, out var job))
    {
        return Results.NotFound();
    }

    var result = job!.Status == ScanStatus.Completed
        ? job.Result?.Select(finding => new ScanFindingResponse(
            finding.RuleId, finding.Description, finding.FilePath, finding.LineNumber)).ToArray()
        : null;
    var error = job.Status == ScanStatus.Failed ? job.Error : null;

    return Results.Ok(new ScanJobResponse(
        job.Id, job.Status.ToString(), job.StatusChangedAt, result, error));
});

app.MapDelete("/api/scans/{id}", (string id, ScanJobRunner runner, ScanJobStore store) =>
{
    if (!Guid.TryParse(id, out var scanId))
    {
        return Results.BadRequest(new { error = "Id must be a valid GUID." });
    }

    if (!store.TryGet(scanId, out _))
    {
        return Results.NotFound();
    }

    var canceled = runner.CancelScan(scanId, out var attemptedAt);
    return Results.Ok(new CancelScanResponse(scanId, canceled, attemptedAt));
});

app.Run();
