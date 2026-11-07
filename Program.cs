using VulnerabilityTracker.Contracts;
using VulnerabilityTracker.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<VulnerabilityStore>();
builder.Services.AddSingleton(_ => new GitLabSourceReader());
builder.Services.AddSingleton<CSharpSourceScanner>();
builder.Services.AddSingleton<RepositoryScanner>();
builder.Services.AddSingleton<ScanJobStore>();
builder.Services.AddSingleton<ScanJobRunner>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<ScanJobRunner>());

var app = builder.Build();

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

app.MapPost("/api/scans", (CreateScanRequest request, ScanJobRunner runner) =>
{
    if (!GitLabSourceReader.IsSupportedUrl(request.RepositoryUrl))
    {
        return Results.BadRequest(new { error = "Use an HTTPS URL of a public gitlab.com project." });
    }

    var id = runner.StartScan(request.RepositoryUrl);
    return Results.Accepted(value: new CreateScanResponse(id));
});

app.Run();
