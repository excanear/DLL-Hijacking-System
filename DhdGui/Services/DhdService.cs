using DhdBridge;
using DhdGui.Models;

namespace DhdGui.Services;

/// <summary>
/// Wraps DhdBridge.DhdBridgeFacade for consumption from the WPF UI layer.
/// All bridge calls that may block are executed in Task.Run by callers.
/// </summary>
public sealed class DhdService : IDhdService, IDisposable
{
    private volatile bool _isInitialized;
    private Action<MonitorFindingModel>? _monitorCallback;
    private readonly object _monitorLock = new();
    private ScanResultManaged? _lastScanResult;  // cache for WriteJsonReport

    public bool IsInitialized      => _isInitialized;
    public bool IsMonitorRunning   => DhdBridgeFacade.IsMonitorRunning();


    public bool Initialize(string policyPath, string hashDbPath, string logDirectory, int pollIntervalMs)
    {
        var cfg = new DhdConfigManaged
        {
            PolicyFilePath       = policyPath,
            HashDbPath           = hashDbPath,
            LogDirectory         = logDirectory,
            MonitorPollIntervalMs = (uint)pollIntervalMs,
        };

        bool ok = DhdBridgeFacade.Initialize(cfg);
        _isInitialized = ok;
        return ok;
    }

    public void Shutdown()
    {
        if (_isInitialized)
        {
            DhdBridgeFacade.StopMonitor();
            DhdBridgeFacade.Shutdown();
            _isInitialized = false;
        }
    }

    public async Task<ValidationResultModel> ValidateDllAsync(string dllPath, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var managed = await Task.Run(() => DhdBridgeFacade.ValidateDll(dllPath), ct);
        return ValidationResultModel.FromManaged(managed);
    }

    public void InvalidateCache() { /* not available in bridge — no-op */ }

    public bool StartMonitor(Action<MonitorFindingModel> callback)
    {
        lock (_monitorLock)
        {
            _monitorCallback = callback;
            return DhdBridgeFacade.StartMonitor(m =>
            {
                var model = MonitorFindingModel.FromManaged(m);
                Action<MonitorFindingModel>? cb;
                lock (_monitorLock)
                    cb = _monitorCallback;
                cb?.Invoke(model);
            });
        }
    }

    public void StopMonitor()
    {
        DhdBridgeFacade.StopMonitor();
        lock (_monitorLock)
            _monitorCallback = null;
    }

    public ulong GetFindingCount()      => DhdBridgeFacade.GetFindingCount();
    public ulong GetDroppedEventCount() => DhdBridgeFacade.GetDroppedEventCount();

    public bool InitializeLogger(string logDirectory) =>
        DhdBridgeFacade.InitializeLogger(logDirectory);

    public void FlushLog() => DhdBridgeFacade.FlushLog();

    public async Task<(List<AuditFindingModel> Findings, ScanSummary Summary)> RunAuditScanAsync(
        ScanOptionsModel options, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        var opts = new ScanOptionsManaged
        {
            TargetExe              = options.TargetExe ?? string.Empty,
            TargetDirectory        = options.TargetDirectory ?? string.Empty,
            CheckPhantomDlls       = options.CheckPhantomDlls,
            CheckWritableDirs      = options.CheckWritableDirs,
            CheckAclPermissiveness = options.CheckAclPermissiveness,
            CheckSearchOrder       = options.CheckSearchOrder,
            IncludeLowSeverity     = options.IncludeLowSeverity,
            MaxRecursionDepth      = (uint)options.MaxRecursionDepth,
            ReportOutputPath       = options.OutputReportPath ?? string.Empty,
        };

        var result = await Task.Run(() => DhdBridgeFacade.RunAuditScan(opts), ct);
        _lastScanResult = result;  // V-02: cache original result for WriteJsonReport

        var findings = result.Findings
            .Select(AuditFindingModel.FromManaged)
            .ToList();

        var summary = new ScanSummary(
            result.ExecutablesScanned,
            result.DllsEvaluated,
            result.PhantomCount,
            result.WritableDirCount,
            result.AclIssueCount,
            result.ScanStart,
            result.ScanEnd);

        return (findings, summary);
    }

    public void WriteJsonReport(List<AuditFindingModel> findings, ScanSummary summary, string outputPath)
    {
        try
        {
            // V-22: reuse the original ScanResultManaged (contains populated Findings list)
            if (_lastScanResult is not null)
            {
                DhdBridgeFacade.WriteJsonReport(_lastScanResult, outputPath);
                return;
            }

            // Fallback: reconstruct without findings (scan result was lost)
            var result = new ScanResultManaged
            {
                ExecutablesScanned = summary.ExecutablesScanned,
                DllsEvaluated      = summary.DllsEvaluated,
                PhantomCount       = summary.PhantomCount,
                WritableDirCount   = summary.WritableDirCount,
                AclIssueCount      = summary.AclIssueCount,
                ScanStart          = summary.ScanStart,
                ScanEnd            = summary.ScanEnd,
            };
            DhdBridgeFacade.WriteJsonReport(result, outputPath);
        }
        finally
        {
            _lastScanResult = null; // V-22: release cache to avoid indefinite memory hold
        }
    }

    public bool   HardenLogDirectory(string path)                => DhdBridgeFacade.HardenLogDirectory(path);
    public bool   HardenPolicyFile(string path)                  => DhdBridgeFacade.HardenPolicyFile(path);
    public bool   VerifyHashDatabaseIntegrity(string dbPath)     => DhdBridgeFacade.VerifyHashDatabaseIntegrity(dbPath);
    public string? SnapshotFileHash(string filePath)             => DhdBridgeFacade.SnapshotFileHash(filePath);
    public bool   VerifyFileIntegrity(string filePath, string expectedHex)
        => DhdBridgeFacade.VerifyFileIntegrity(filePath, expectedHex);

    public void Dispose() => Shutdown();
}
