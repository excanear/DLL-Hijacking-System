using DhdBridge;

namespace DhdGui.Models;

public class ValidationResultModel
{
    public double PathScore      { get; init; }
    public double NameScore      { get; init; }
    public double HashScore      { get; init; }
    public double SignatureScore { get; init; }
    public double AggregateScore { get; init; }

    public RiskLevelManaged     RiskLevel      { get; init; }
    public BlockReasonManaged   BlockReasons   { get; init; }
    public WhitelistTierManaged WhitelistTier  { get; init; }

    public string Sha256Hex        { get; init; } = string.Empty;
    public bool   SignaturePresent { get; init; }
    public bool   SignatureValid   { get; init; }
    public bool   SignatureRevoked { get; init; }
    public string CertSubject      { get; init; } = string.Empty;
    public string CertIssuer       { get; init; } = string.Empty;
    public bool   ServedFromCache  { get; init; }
    public string FailureReason    { get; init; } = string.Empty;

    public LoadActionManaged LoadAction { get; init; }

    public static ValidationResultModel FromManaged(ValidationResultManaged m) => new()
    {
        PathScore      = m.PathScore,
        NameScore      = m.NameScore,
        HashScore      = m.HashScore,
        SignatureScore = m.SignatureScore,
        AggregateScore = m.AggregateScore,
        RiskLevel      = m.RiskLevel,
        BlockReasons   = m.BlockReasons,
        WhitelistTier  = m.WhitelistTier,
        Sha256Hex      = m.Sha256Hex ?? string.Empty,
        SignaturePresent = m.SignaturePresent,
        SignatureValid   = m.SignatureValid,
        SignatureRevoked = m.SignatureRevoked,
        CertSubject    = m.CertSubject ?? string.Empty,
        CertIssuer     = m.CertIssuer  ?? string.Empty,
        ServedFromCache = m.ServedFromCache,
        FailureReason  = m.FailureReason ?? string.Empty,
        LoadAction     = m.RecommendedAction,
    };
}
