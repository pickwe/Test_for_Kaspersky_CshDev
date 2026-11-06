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

    [TestMethod]
    public void FindsLiteralKeyInAesGcmConstructor()
    {
        const string source = "var cipher = new AesGcm(new byte[] { 1, 2, 3 }, 16);";

        var findings = new CSharpSourceScanner().Scan("Crypto.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual(new ScanFinding(
            "CRYPTO001", "An encryption key is written directly in source code.", "Crypto.cs", 1), findings[0]);
    }

    [TestMethod]
    public void FindsLiteralKeyWithFullyQualifiedType()
    {
        const string source = "var cipher = new System.Security.Cryptography.AesGcm(new byte[] { 1, 2, 3 }, 16);";

        var findings = new CSharpSourceScanner().Scan("QualifiedCrypto.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual("CRYPTO001", findings[0].RuleId);
    }

    [TestMethod]
    public void FindsLiteralKeyWithInferredArrayType()
    {
        const string source = "var cipher = new AesGcm(new[] { (byte)1, (byte)2, (byte)3 }, 16);";

        var findings = new CSharpSourceScanner().Scan("InferredArray.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual("CRYPTO001", findings[0].RuleId);
    }

    [TestMethod]
    public void IgnoresKeyProvidedByVariable()
    {
        const string source = "var cipher = new AesGcm(key, 16);";

        var findings = new CSharpSourceScanner().Scan("SafeCrypto.cs", source);

        Assert.AreEqual(0, findings.Count);
    }
}
