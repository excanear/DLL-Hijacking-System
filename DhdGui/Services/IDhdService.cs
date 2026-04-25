using DhdBridge;
using DhdGui.Models;

namespace DhdGui.Services;

public interface IDhdService
{
    // System lifecycle
    bool Initialize(string policyPath, string hashDbPath, string logDirectory, int pollIntervalMs);
    void Shutdown();
    bool IsInitialized { get; }

    // Validator
    Task<ValidationResultModel> ValidateDllAsync(string dllPath, CancellationToken ct = default);

    // Monitor
    bool StartMonitor(Action<MonitorFindingModel> callback);
    void StopMonitor();
    bool IsMonitorRunning { get; }
    ulong GetFindingCount();

    // Logger
    bool InitializeLogger(string logDirectory);
    void FlushLog();
    ulong GetDroppedEventCount();

    // Audit
    Task<(List<AuditFindingModel> Findings, ScanSummary Summary)> RunAuditScanAsync(
        ScanOptionsModel options, CancellationToken ct = default);
    void WriteJsonReport(List<AuditFindingModel> findings, ScanSummary summary, string outputPath);

    // Hardening
    bool HardenLogDirectory(string path);
    bool HardenPolicyFile(string path);
    bool VerifyHashDatabaseIntegrity(string dbPath);
    string? SnapshotFileHash(string filePath);
    bool VerifyFileIntegrity(string filePath, string expectedHex);
}

public record ScanSummary(
    uint ExecutablesScanned,
    uint DllsEvaluated,
    uint PhantomCount,
    uint WritableDirCount,
    uint AclIssueCount,
    DateTime ScanStart,
    DateTime ScanEnd);

public record ScanOptionsModel(
    string? TargetExe,
    string? TargetDirectory,
    bool CheckPhantomDlls,
    bool CheckWritableDirs,
    bool CheckAclPermissiveness,
    bool CheckSearchOrder,
    bool IncludeLowSeverity,
    int  MaxRecursionDepth,
    string? OutputReportPath);
