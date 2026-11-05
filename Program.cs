using VulnerabilityTracker.Contracts;
using VulnerabilityTracker.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<VulnerabilityStore>();

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

app.Run();
