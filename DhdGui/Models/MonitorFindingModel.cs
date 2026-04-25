using DhdBridge;

namespace DhdGui.Models;

public class MonitorFindingModel
{
    public nint     ModuleBase         { get; init; }
    public string   ModulePath         { get; init; } = string.Empty;
    public string   ModuleName         { get; init; } = string.Empty;
    public DateTime DetectedAt         { get; init; }
    public bool     DetectedByEtw      { get; init; }
    public BlockReasonManaged BlockReasons { get; init; }
    public string   BlockReasonsDecoded { get; init; } = string.Empty;

    public static MonitorFindingModel FromManaged(MonitorFindingManaged m) => new()
    {
        ModuleBase          = m.ModuleBase,
        ModulePath          = m.ModulePath ?? string.Empty,
        ModuleName          = m.ModuleName ?? string.Empty,
        DetectedAt          = m.DetectedAt,
        DetectedByEtw       = m.DetectedByEtw,
        BlockReasons        = m.BlockReasons,
        BlockReasonsDecoded = m.BlockReasonsDecoded ?? string.Empty,
    };
}
