using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace VulnerabilityTracker.Services;

public sealed record ScanFinding(string RuleId, string Description, string FilePath, int LineNumber);

public sealed class CSharpSourceScanner
{
    public IReadOnlyList<ScanFinding> Scan(string filePath, string sourceCode)
    {
        var tree = CSharpSyntaxTree.ParseText(sourceCode, path: filePath);
        var findings = new List<ScanFinding>();

        foreach (var assignment in tree.GetRoot().DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!IsCertificateCallback(assignment) || !AlwaysAcceptsCertificate(assignment.Right))
            {
                continue;
            }

            var lineNumber = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            findings.Add(new ScanFinding(
                "TLS001",
                "Certificate validation always returns true.",
                filePath,
                lineNumber));
        }

        return findings;
    }

    private static bool IsCertificateCallback(AssignmentExpressionSyntax assignment)
    {
        var name = assignment.Left switch
        {
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            IdentifierNameSyntax identifier when assignment.Parent is InitializerExpressionSyntax =>
                identifier.Identifier.ValueText,
            _ => null
        };

        return name is "ServerCertificateCustomValidationCallback" or "ServerCertificateValidationCallback";
    }

    private static bool AlwaysAcceptsCertificate(ExpressionSyntax expression)
    {
        if (expression is not LambdaExpressionSyntax lambda)
        {
            return false;
        }

        if (lambda.Body is ExpressionSyntax bodyExpression)
        {
            return bodyExpression.IsKind(SyntaxKind.TrueLiteralExpression);
        }

        return lambda.Body is BlockSyntax block &&
            block.Statements.Count == 1 &&
            block.Statements[0] is ReturnStatementSyntax returnStatement &&
            returnStatement.Expression?.IsKind(SyntaxKind.TrueLiteralExpression) == true;
    }
}
