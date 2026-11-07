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

        foreach (var creation in tree.GetRoot().DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var firstArgument = creation.ArgumentList?.Arguments.FirstOrDefault()?.Expression;

            if (HasTypeName(creation.Type, "AesGcm") &&
                firstArgument is ArrayCreationExpressionSyntax or ImplicitArrayCreationExpressionSyntax)
            {
                var lineNumber = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                findings.Add(new ScanFinding(
                    "CRYPTO001",
                    "An encryption key is written directly in source code.",
                    filePath,
                    lineNumber));
            }

            if (HasTypeName(creation.Type, "SqlCommand") && IsDynamicSql(firstArgument))
            {
                var lineNumber = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                findings.Add(new ScanFinding(
                    "SQL001",
                    "A SQL query is built from dynamic text; use parameters instead.",
                    filePath,
                    lineNumber));
            }
        }

        var formatterVariables = tree.GetRoot().DescendantNodes()
            .OfType<VariableDeclaratorSyntax>()
            .Where(variable => variable.Initializer?.Value is ObjectCreationExpressionSyntax creation &&
                HasTypeName(creation.Type, "BinaryFormatter"))
            .Select(variable => variable.Identifier.ValueText)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var invocation in tree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax method ||
                method.Name.Identifier.ValueText != "Deserialize")
            {
                continue;
            }

            var usesBinaryFormatter = method.Expression switch
            {
                ObjectCreationExpressionSyntax creation => HasTypeName(creation.Type, "BinaryFormatter"),
                IdentifierNameSyntax name => formatterVariables.Contains(name.Identifier.ValueText),
                _ => false
            };

            if (usesBinaryFormatter)
            {
                var lineNumber = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                findings.Add(new ScanFinding(
                    "SERIAL001",
                    "BinaryFormatter.Deserialize can process unsafe input.",
                    filePath,
                    lineNumber));
            }
        }

        return findings;
    }

    private static bool HasTypeName(TypeSyntax type, string expectedName) => type switch
    {
        IdentifierNameSyntax name => name.Identifier.ValueText == expectedName,
        QualifiedNameSyntax name => name.Right.Identifier.ValueText == expectedName,
        _ => false
    };

    private static bool IsDynamicSql(ExpressionSyntax? expression) => expression switch
    {
        InterpolatedStringExpressionSyntax text => text.Contents.OfType<InterpolationSyntax>()
            .Any(part => part.Expression is not LiteralExpressionSyntax &&
                !IsConstantText(part.Expression)),
        BinaryExpressionSyntax addition when addition.IsKind(SyntaxKind.AddExpression) =>
            !IsConstantText(addition),
        _ => false
    };

    private static bool IsConstantText(ExpressionSyntax expression) => expression switch
    {
        LiteralExpressionSyntax text => text.IsKind(SyntaxKind.StringLiteralExpression),
        BinaryExpressionSyntax addition when addition.IsKind(SyntaxKind.AddExpression) =>
            IsConstantText(addition.Left) && IsConstantText(addition.Right),
        ParenthesizedExpressionSyntax parenthesized => IsConstantText(parenthesized.Expression),
        _ => false
    };

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
