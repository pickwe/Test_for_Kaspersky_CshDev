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

    [TestMethod]
    public void FindsInterpolatedSqlQuery()
    {
        const string source = """
            var command = new SqlCommand(
                $"SELECT * FROM Users WHERE Name = '{name}'", connection);
            """;

        var findings = new CSharpSourceScanner().Scan("Users.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual(new ScanFinding(
            "SQL001", "A SQL query is built from dynamic text; use parameters instead.",
            "Users.cs", 1), findings[0]);
    }

    [TestMethod]
    public void FindsConcatenatedSqlQueryWithQualifiedType()
    {
        const string source = "var command = new System.Data.SqlClient.SqlCommand(\"SELECT * FROM Users WHERE Id = \" + userId, connection);";

        var findings = new CSharpSourceScanner().Scan("Users.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual("SQL001", findings[0].RuleId);
    }

    [TestMethod]
    public void IgnoresParameterizedAndConstantSqlQueries()
    {
        const string source = """
            var safe = new SqlCommand("SELECT * FROM Users WHERE Id = @id", connection);
            safe.Parameters.AddWithValue("@id", userId);
            var constant = new SqlCommand("SELECT * " + "FROM Users", connection);
            """;

        var findings = new CSharpSourceScanner().Scan("SafeSql.cs", source);

        Assert.AreEqual(0, findings.Count);
    }

    [TestMethod]
    public void FindsDeserializeOnBinaryFormatterVariable()
    {
        const string source = """
            var formatter = new BinaryFormatter();
            var value = formatter.Deserialize(stream);
            """;

        var findings = new CSharpSourceScanner().Scan("Import.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual(new ScanFinding(
            "SERIAL001", "BinaryFormatter.Deserialize can process unsafe input.",
            "Import.cs", 2), findings[0]);
    }

    [TestMethod]
    public void FindsDeserializeOnDirectFullyQualifiedConstruction()
    {
        const string source = "new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter().Deserialize(stream);";

        var findings = new CSharpSourceScanner().Scan("LegacyImport.cs", source);

        Assert.AreEqual(1, findings.Count);
        Assert.AreEqual("SERIAL001", findings[0].RuleId);
    }

    [TestMethod]
    public void IgnoresOtherDeserializersAndTextMentions()
    {
        const string source = """
            // new BinaryFormatter().Deserialize(stream);
            var example = "formatter.Deserialize(stream)";
            var value = JsonSerializer.Deserialize<Data>(json);
            """;

        var findings = new CSharpSourceScanner().Scan("SafeImport.cs", source);

        Assert.AreEqual(0, findings.Count);
    }
}
