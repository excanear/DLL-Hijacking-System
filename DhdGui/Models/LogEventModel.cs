using DhdBridge;

namespace DhdGui.Models;

public class LogEventModel
{
    public DateTime          Timestamp    { get; init; }
    public LogSeverityManaged Severity    { get; init; }
    public string            SourceModule { get; init; } = string.Empty;
    public string            HostName     { get; init; } = string.Empty;
    public string            ProcessName  { get; init; } = string.Empty;
    public int               ProcessId    { get; init; }
    public string            DllPath      { get; init; } = string.Empty;
    public double            TrustScore   { get; init; }
    public LoadActionManaged Action       { get; init; }
    public BlockReasonManaged BlockReasons { get; init; }
    public RiskLevelManaged  RiskLevel    { get; init; }
    public bool              HmacPresent  { get; init; }
}
