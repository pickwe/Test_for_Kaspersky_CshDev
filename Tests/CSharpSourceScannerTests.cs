using Microsoft.VisualStudio.TestTools.UnitTesting;
using VulnerabilityTracker.Services;

namespace VulnerabilityTracker.Tests;

[TestClass]
public sealed class CSharpSourceScannerTests
{
    [TestMethod]
    public void FindsCallbackThatAlwaysAcceptsCertificates()
    {
        const string source = """
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            """;

        var findings = new CSharpSourceScanner().Scan("Network.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual(new ScanFinding(
            "TLS001", "Certificate validation always returns true.", "Network.cs", 3), findings[0]);
    }

    [TestMethod]
    public void FindsBlockLambdaThatAlwaysAcceptsCertificates()
    {
        const string source = """
            ServicePointManager.ServerCertificateValidationCallback +=
                (_, _, _, _) => { return true; };
            """;

        var findings = new CSharpSourceScanner().Scan("Legacy.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual(1, findings[0].LineNumber);
    }

    [TestMethod]
    public void IgnoresValidCallbackAndTextThatOnlyMentionsUnsafeCode()
    {
        const string source = """
            // ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            var example = "ServerCertificateCustomValidationCallback = (_, _, _, _) => true";
            handler.ServerCertificateCustomValidationCallback = (_, _, _, errors) =>
                errors == SslPolicyErrors.None;
            """;

        var findings = new CSharpSourceScanner().Scan("Safe.cs", source);

        Assert.AreEqual(0, findings.Count);
    }
}
