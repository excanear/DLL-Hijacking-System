using DhdBridge;

namespace DhdGui.Models;

public class AuditFindingModel
{
    public RiskLevelManaged Severity       { get; init; }
    public string           TargetPath     { get; init; } = string.Empty;
    public string           DllName        { get; init; } = string.Empty;
    public string           IssueCode      { get; init; } = string.Empty;
    public string           Detail         { get; init; } = string.Empty;
    public string           Recommendation { get; init; } = string.Empty;

    public static AuditFindingModel FromManaged(AuditFindingManaged m) => new()
    {
        Severity       = m.Severity,
        TargetPath     = m.TargetPath     ?? string.Empty,
        DllName        = m.DllName        ?? string.Empty,
        IssueCode      = m.IssueCode      ?? string.Empty,
        Detail         = m.Detail         ?? string.Empty,
        Recommendation = m.Recommendation ?? string.Empty,
    };
}
