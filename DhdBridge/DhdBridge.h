#pragma once
// =============================================================================
// DhdBridge.h
// C++/CLI managed wrapper over the native DLL Hijacking Defense System.
// Compiled with /clr into DhdBridge.dll.
//
// All ref classes are in the DhdBridge namespace.
// =============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Runtime::InteropServices;
using namespace System::Threading;

namespace DhdBridge {

// ---------------------------------------------------------------------------
// Enums — mirror dhd:: enums exactly (same underlying values)
// ---------------------------------------------------------------------------

public enum class RiskLevelManaged : unsigned int {
    Low      = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3
};

public enum class PolicyModeManaged : unsigned int {
    Audit  = 0,
    Strict = 1
};

public enum class LoadActionManaged : unsigned int {
    Allowed        = 0,
    AllowedFlagged = 1,
    Blocked        = 2,
    BlockedAlways  = 3
};

public enum class LogSeverityManaged : unsigned int {
    Info    = 0,
    Warning = 1,
    Alert   = 2
};

public enum class WhitelistTierManaged : unsigned int {
    None  = 0,
    Tier1 = 1,
    Tier2 = 2,
    Tier3 = 3
};

[Flags]
public enum class BlockReasonManaged : unsigned int {
    None                  = 0x00000000,
    PathRelative          = 0x00000001,
    PathNotInWhitelist    = 0x00000002,
    PathInBlockedDir      = 0x00000004,
    PathIsUnc             = 0x00000008,
    SymlinkResolutionFail = 0x00000010,
    NameHomoglyph         = 0x00000020,
    NameTyposquatting     = 0x00000040,
    NameSuspiciousPattern = 0x00000080,
    HashNotFound          = 0x00000100,
    HashRevoked           = 0x00000200,
    HashComputeFailure    = 0x00000400,
    SignatureInvalid       = 0x00000800,
    SignatureAbsent        = 0x00001000,
    SignatureRevoked       = 0x00002000,
    ScoreTooLow           = 0x00004000,
    RuleSystemDllOutside  = 0x00008000,
    RuleTempDirectory     = 0x00010000,
    RulePrivilegedProcess = 0x00020000,
    ToctouDetected        = 0x00040000,
    UnexpectedModule      = 0x00080000
};

// ---------------------------------------------------------------------------
// Managed data transfer objects
// ---------------------------------------------------------------------------

public ref class ValidationResultManaged {
public:
    property double PathScore;
    property double NameScore;
    property double HashScore;
    property double SignatureScore;
    property double AggregateScore;
    property RiskLevelManaged RiskLevel;
    property BlockReasonManaged BlockReasons;
    property WhitelistTierManaged WhitelistTier;
    property String^ Sha256Hex;
    property bool SignaturePresent;
    property bool SignatureValid;
    property bool SignatureRevoked;
    property String^ CertSubject;
    property String^ CertIssuer;
    property bool ServedFromCache;
    property String^ FailureReason;
    property LoadActionManaged RecommendedAction;
};

public ref class MonitorFindingManaged {
public:
    property IntPtr ModuleBase;
    property String^ ModulePath;
    property String^ ModuleName;
    property DateTime DetectedAt;
    property bool DetectedByEtw;
    property BlockReasonManaged BlockReasons;
    property String^ BlockReasonsDecoded;
};

public ref class LogEventManaged {
public:
    property DateTime Timestamp;
    property LogSeverityManaged Severity;
    property String^ SourceModule;
    property String^ HostName;
    property String^ ProcessName;
    property String^ DllPath;
    property int ProcessId;
    property double TrustScore;
    property LoadActionManaged Action;
    property BlockReasonManaged BlockReasons;
    property RiskLevelManaged RiskLevel;
    property bool HmacPresent;
};

public ref class AuditFindingManaged {
public:
    property RiskLevelManaged Severity;
    property String^ TargetPath;
    property String^ DllName;
    property String^ IssueCode;
    property String^ Detail;
    property String^ Recommendation;
};

public ref class ScanResultManaged {
public:
    property List<AuditFindingManaged^>^ Findings;
    property unsigned int ExecutablesScanned;
    property unsigned int DllsEvaluated;
    property unsigned int PhantomCount;
    property unsigned int WritableDirCount;
    property unsigned int AclIssueCount;
    property DateTime ScanStart;
    property DateTime ScanEnd;

    ScanResultManaged() { Findings = gcnew List<AuditFindingManaged^>(); }
};

public ref class DhdConfigManaged {
public:
    property String^ PolicyFilePath;
    property String^ HashDbPath;
    property String^ LogDirectory;
    property unsigned int MonitorPollIntervalMs;

    DhdConfigManaged() {
        PolicyFilePath       = "policy\\defaults.json";
        HashDbPath           = "config\\hash_database.json";
        LogDirectory         = "logs";
        MonitorPollIntervalMs = 5000;
    }
};

public ref class ScanOptionsManaged {
public:
    property String^ TargetExe;
    property String^ TargetDirectory;
    property unsigned int MaxRecursionDepth;
    property bool CheckPhantomDlls;
    property bool CheckWritableDirs;
    property bool CheckAclPermissiveness;
    property bool CheckSearchOrder;
    property String^ ReportOutputPath;
    property bool IncludeLowSeverity;

    ScanOptionsManaged() {
        TargetExe              = String::Empty;
        TargetDirectory        = String::Empty;
        MaxRecursionDepth      = 5;
        CheckPhantomDlls       = true;
        CheckWritableDirs      = true;
        CheckAclPermissiveness = true;
        CheckSearchOrder       = true;
        ReportOutputPath       = String::Empty;
        IncludeLowSeverity     = false;
    }
};

// ---------------------------------------------------------------------------
// Main bridge facade
// ---------------------------------------------------------------------------

public ref class DhdBridgeFacade sealed {
public:
    // DefenseSystem
    static bool Initialize(DhdConfigManaged^ config);
    static void Shutdown();
    static bool IsInitialized();

    // Validator
    static ValidationResultManaged^ ValidateDll(String^ path);

    // AuditScanner
    static ScanResultManaged^ RunAuditScan(ScanOptionsManaged^ options);
    static bool WriteJsonReport(ScanResultManaged^ result, String^ outputPath);

    // Monitor
    static bool StartMonitor(Action<MonitorFindingManaged^>^ callback);
    static void StopMonitor();
    static bool IsMonitorRunning();
    static void ForcePollingSnapshot();
    static unsigned long long GetFindingCount();

    // LoggingEngine
    static bool InitializeLogger(String^ logDir);
    static void ShutdownLogger();
    static bool IsLoggerInitialized();
    static void FlushLog();
    static unsigned long long GetDroppedEventCount();

    // Hardening
    static bool HardenLogDirectory(String^ path);
    static bool HardenPolicyFile(String^ path);
    static bool VerifyHashDatabaseIntegrity(String^ dbPath);
    static String^ SnapshotFileHash(String^ filePath);
    static bool VerifyFileIntegrity(String^ filePath, String^ expectedHex);

private:
    // Managed delegate matching native MonitorCallback ABI.
    // 'const MonitorFinding&' becomes IntPtr (pointer) at the ABI boundary.
    [System::Runtime::InteropServices::UnmanagedFunctionPointer(
        System::Runtime::InteropServices::CallingConvention::Cdecl)]
    delegate void MonitorNativeDelegate(IntPtr findingPtr, IntPtr userData);

    // Holds GCHandle for the Action<> callback passed by the caller
    static GCHandle s_monitorCallbackHandle;
    static bool     s_monitorCallbackHandleAllocated = false;

    // Holds GCHandle for the native-callable delegate (prevents thunk GC)
    static MonitorNativeDelegate^ s_nativeDelegate;
    static GCHandle               s_nativeDelegateHandle;
    static bool                   s_nativeDelegateAllocated = false;

    // Managed shim invoked by the native->managed thunk
    static void MonitorNativeShim(IntPtr findingPtr, IntPtr userData);
};

} // namespace DhdBridge
