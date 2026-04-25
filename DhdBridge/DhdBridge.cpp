// =============================================================================
// DhdBridge.cpp
// C++/CLI managed-to-native bridge implementation.
// Compile with /clr (not /clr:pure).
//
// Links against: core.lib, intelligence.lib, monitor.lib, audit.lib, shared.lib
// plus their transitive Win32 deps (wintrust, crypt32, bcrypt, advapi32, etc.)
// =============================================================================

// Prevent <windows.h> included by native headers from conflicting with CLR
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Native C++ headers — included before any managed code
#pragma unmanaged
#include <windows.h>
#pragma managed

// msclr interop for wchar_t <-> System::String^ marshaling
#include <msclr/marshal.h>
#include <msclr/marshal_windows.h>

// Native DHD headers
#include "../dll-hijack-defense/core/defense_system.h"
#include "../dll-hijack-defense/core/dll_validator.h"
#include "../dll-hijack-defense/core/hardening.h"
#include "../dll-hijack-defense/intelligence/logging_engine.h"
#include "../dll-hijack-defense/monitor/runtime_monitor.h"
#include "../dll-hijack-defense/audit/audit_scanner.h"
#include "../dll-hijack-defense/shared/types.h"
#include "../dll-hijack-defense/shared/constants.h"

#include "DhdBridge.h"

using namespace System;
using namespace System::Runtime::InteropServices;
using namespace msclr::interop;

// ---------------------------------------------------------------------------
// Internal helpers (file-scope, not exposed)
// ---------------------------------------------------------------------------

namespace {

    // Converts a FILETIME to a managed DateTime (UTC)
    DateTime FiletimeToDateTimeImpl(const FILETIME& ft)
    {
        ULARGE_INTEGER uli;
        uli.LowPart  = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        // FILETIME epoch: January 1, 1601. DateTime epoch: January 1, 0001.
        // Difference in 100-ns ticks:
        Int64 ticks = static_cast<Int64>(uli.QuadPart);
        return DateTime::FromFileTimeUtc(ticks);
    }

    // Marshal managed String^ -> native wchar_t buffer (safe, no heap alloc)
    // Returns false if path is null/empty or too long for MAX_PATH.
    bool MarshalString(String^ managed, wchar_t* buf, size_t bufCch)
    {
        if (managed == nullptr || managed->Length == 0) {
            buf[0] = L'\0';
            return true;
        }
        if (static_cast<size_t>(managed->Length) >= bufCch)
            return false;
        pin_ptr<const wchar_t> pinned = PtrToStringChars(managed);
        wcscpy_s(buf, bufCch, pinned);
        return true;
    }

    // Decode BlockReason bitfield to human-readable string list
    String^ DecodeBlockReasonsImpl(DhdBridge::BlockReasonManaged reasons)
    {
        using BR = DhdBridge::BlockReasonManaged;
        auto parts = gcnew System::Collections::Generic::List<String^>();

        if ((reasons & BR::PathRelative)          != BR::None) parts->Add("Caminho relativo");
        if ((reasons & BR::PathNotInWhitelist)    != BR::None) parts->Add("Caminho fora da whitelist");
        if ((reasons & BR::PathInBlockedDir)      != BR::None) parts->Add("Caminho em diretório bloqueado");
        if ((reasons & BR::PathIsUnc)             != BR::None) parts->Add("Caminho UNC rejeitado");
        if ((reasons & BR::SymlinkResolutionFail) != BR::None) parts->Add("Falha ao resolver symlink");
        if ((reasons & BR::NameHomoglyph)         != BR::None) parts->Add("Nome com caracteres homóglifos");
        if ((reasons & BR::NameTyposquatting)     != BR::None) parts->Add("Nome com typosquatting");
        if ((reasons & BR::NameSuspiciousPattern) != BR::None) parts->Add("Padrão de nome suspeito");
        if ((reasons & BR::HashNotFound)          != BR::None) parts->Add("Hash não encontrado na base de dados");
        if ((reasons & BR::HashRevoked)           != BR::None) parts->Add("Hash revogado");
        if ((reasons & BR::HashComputeFailure)    != BR::None) parts->Add("Falha ao calcular hash");
        if ((reasons & BR::SignatureInvalid)      != BR::None) parts->Add("Assinatura Authenticode inválida");
        if ((reasons & BR::SignatureAbsent)       != BR::None) parts->Add("DLL sem assinatura");
        if ((reasons & BR::SignatureRevoked)      != BR::None) parts->Add("Certificado revogado");
        if ((reasons & BR::ScoreTooLow)           != BR::None) parts->Add("Score de confiança abaixo do limite");
        if ((reasons & BR::RuleSystemDllOutside)  != BR::None) parts->Add("DLL de sistema fora do System32 (R001)");
        if ((reasons & BR::RuleTempDirectory)     != BR::None) parts->Add("DLL em diretório temporário (R003)");
        if ((reasons & BR::RulePrivilegedProcess) != BR::None) parts->Add("DLL não vettada em processo privilegiado (R006)");
        if ((reasons & BR::ToctouDetected)        != BR::None) parts->Add("TOCTOU detectado (arquivo alterado entre validação e carga)");
        if ((reasons & BR::UnexpectedModule)      != BR::None) parts->Add("Módulo carregado sem passar pelo SecureLoader");

        if (parts->Count == 0) return "Nenhum";
        return String::Join("; ", parts);
    }

} // anonymous namespace

// ---------------------------------------------------------------------------
// Monitor callback bridge
// ---------------------------------------------------------------------------

namespace {

    // Converts native MonitorFinding -> managed MonitorFindingManaged
    DhdBridge::MonitorFindingManaged^ MarshalMonitorFinding(const dhd::MonitorFinding& f)
    {
        auto m = gcnew DhdBridge::MonitorFindingManaged();
        m->ModuleBase    = IntPtr(f.module_base);
        m->ModulePath    = gcnew String(f.module_path);
        m->ModuleName    = gcnew String(f.module_name);
        m->DetectedAt    = FiletimeToDateTimeImpl(f.detected_at);
        m->DetectedByEtw = (f.detected_by_etw != FALSE);
        m->BlockReasons  = static_cast<DhdBridge::BlockReasonManaged>(f.block_reasons);
        m->BlockReasonsDecoded = DecodeBlockReasonsImpl(m->BlockReasons);
        return m;
    }

} // anonymous namespace

namespace DhdBridge {

    // Managed shim — invoked via the native->managed thunk created by
    // Marshal::GetFunctionPointerForDelegate in StartMonitor.
    void DhdBridgeFacade::MonitorNativeShim(IntPtr findingPtr, IntPtr /*userData*/)
    {
        if (!s_monitorCallbackHandleAllocated) return;
        const dhd::MonitorFinding* f =
            static_cast<const dhd::MonitorFinding*>(findingPtr.ToPointer());
        MonitorFindingManaged^ managed = MarshalMonitorFinding(*f);
        auto cb = safe_cast<Action<MonitorFindingManaged^>^>(
            s_monitorCallbackHandle.Target);
        if (cb != nullptr) cb->Invoke(managed);
    }

} // namespace DhdBridge

// =============================================================================
// DefenseSystem
// =============================================================================

namespace DhdBridge {

bool DhdBridgeFacade::Initialize(DhdConfigManaged^ config)
{
    if (config == nullptr)
        throw gcnew ArgumentNullException("config");

    dhd::DefenseSystemConfig nativeCfg;

    if (!MarshalString(config->PolicyFilePath, nativeCfg.policy_file_path,
                       _countof(nativeCfg.policy_file_path)))
        throw gcnew ArgumentException("PolicyFilePath exceeds MAX_PATH");

    if (!MarshalString(config->HashDbPath, nativeCfg.hash_db_path,
                       _countof(nativeCfg.hash_db_path)))
        throw gcnew ArgumentException("HashDbPath exceeds MAX_PATH");

    if (!MarshalString(config->LogDirectory, nativeCfg.log_directory,
                       _countof(nativeCfg.log_directory)))
        throw gcnew ArgumentException("LogDirectory exceeds MAX_PATH");

    nativeCfg.monitor_poll_interval_ms = config->MonitorPollIntervalMs;
    nativeCfg.monitor_callback         = nullptr;
    nativeCfg.monitor_user_data        = nullptr;

    BOOL result = dhd::InitializeDefenseSystem(&nativeCfg);
    if (!result) {
        DWORD err = GetLastError();
        throw gcnew InvalidOperationException(
            String::Format("InitializeDefenseSystem falhou. Win32 error: {0}", err));
    }
    return true;
}

void DhdBridgeFacade::Shutdown()
{
    dhd::ShutdownDefenseSystem();
}

bool DhdBridgeFacade::IsInitialized()
{
    return dhd::IsDefenseSystemInitialized() != FALSE;
}

// =============================================================================
// DLL Validator
// =============================================================================

ValidationResultManaged^ DhdBridgeFacade::ValidateDll(String^ path)
{
    if (String::IsNullOrWhiteSpace(path))
        throw gcnew ArgumentNullException("path");
    if (!path->EndsWith(".dll", StringComparison::OrdinalIgnoreCase))
        throw gcnew ArgumentException("O arquivo deve ter extensão .dll");
    if (path->Length >= MAX_PATH)
        throw gcnew ArgumentException("Caminho excede MAX_PATH");

    wchar_t nativePath[MAX_PATH];
    if (!MarshalString(path, nativePath, _countof(nativePath)))
        throw gcnew ArgumentException("Caminho inválido");

    // Open file handle for validation (GENERIC_READ, FILE_SHARE_READ only)
    HANDLE hFile = CreateFileW(
        nativePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        throw gcnew System::IO::FileNotFoundException(
            String::Format("Não foi possível abrir o arquivo. Win32 error: {0}", err),
            path);
    }

    // Resolve canonical path (eliminates symlinks/junctions)
    wchar_t canonicalPath[MAX_PATH] = {};
    DWORD len = GetFinalPathNameByHandleW(hFile, canonicalPath,
                                          _countof(canonicalPath),
                                          FILE_NAME_NORMALIZED);
    if (len == 0 || len >= MAX_PATH) {
        CloseHandle(hFile);
        throw gcnew InvalidOperationException("Falha ao resolver caminho canônico");
    }

    dhd::ValidationResult nativeResult = {};
    BOOL ok = dhd::ValidateDLL(hFile, canonicalPath, TRUE, &nativeResult);
    CloseHandle(hFile);

    if (!ok) {
        DWORD err = GetLastError();
        throw gcnew InvalidOperationException(
            String::Format("ValidateDLL falhou internamente. Win32 error: {0}", err));
    }

    auto m = gcnew ValidationResultManaged();
    m->PathScore        = static_cast<double>(nativeResult.path_score);
    m->NameScore        = static_cast<double>(nativeResult.name_score);
    m->HashScore        = static_cast<double>(nativeResult.hash_score);
    m->SignatureScore   = static_cast<double>(nativeResult.signature_score);
    m->AggregateScore   = static_cast<double>(nativeResult.aggregate_score);
    m->RiskLevel        = static_cast<RiskLevelManaged>(nativeResult.risk_level);
    m->BlockReasons     = static_cast<BlockReasonManaged>(nativeResult.block_reasons);
    m->WhitelistTier    = static_cast<WhitelistTierManaged>(nativeResult.whitelist_tier);
    m->Sha256Hex        = gcnew String(nativeResult.sha256_hex);
    m->SignaturePresent = (nativeResult.signature_present != FALSE);
    m->SignatureValid   = (nativeResult.signature_valid   != FALSE);
    m->SignatureRevoked = (nativeResult.signature_revoked != FALSE);
    m->CertSubject      = gcnew String(nativeResult.cert_subject);
    m->CertIssuer       = gcnew String(nativeResult.cert_issuer);
    m->ServedFromCache  = (nativeResult.served_from_cache != FALSE);
    m->FailureReason    = gcnew String(nativeResult.failure_reason);

    // Derive recommended action using the same thresholds as the native layer
    float score = nativeResult.aggregate_score;
    if      (score > dhd::THRESHOLD_BLOCK_ALWAYS) m->RecommendedAction = LoadActionManaged::BlockedAlways;
    else if (score > dhd::THRESHOLD_BLOCK_STRICT) m->RecommendedAction = LoadActionManaged::Blocked;
    else if (score > dhd::THRESHOLD_WARN)         m->RecommendedAction = LoadActionManaged::AllowedFlagged;
    else                                           m->RecommendedAction = LoadActionManaged::Allowed;

    return m;
}

// =============================================================================
// Audit Scanner
// =============================================================================

ScanResultManaged^ DhdBridgeFacade::RunAuditScan(ScanOptionsManaged^ options)
{
    if (options == nullptr)
        throw gcnew ArgumentNullException("options");

    dhd::ScanOptions nativeOpts;

    MarshalString(options->TargetExe,        nativeOpts.target_exe,        _countof(nativeOpts.target_exe));
    MarshalString(options->TargetDirectory,  nativeOpts.target_directory,  _countof(nativeOpts.target_directory));
    MarshalString(options->ReportOutputPath, nativeOpts.report_output_path,_countof(nativeOpts.report_output_path));

    nativeOpts.max_recursion_depth     = options->MaxRecursionDepth;
    nativeOpts.check_phantom_dlls      = options->CheckPhantomDlls      ? TRUE : FALSE;
    nativeOpts.check_writable_dirs     = options->CheckWritableDirs      ? TRUE : FALSE;
    nativeOpts.check_acl_permissiveness= options->CheckAclPermissiveness ? TRUE : FALSE;
    nativeOpts.check_search_order      = options->CheckSearchOrder       ? TRUE : FALSE;
    nativeOpts.include_low_severity    = options->IncludeLowSeverity     ? TRUE : FALSE;

    dhd::ScanResult nativeResult = {};
    BOOL ok = dhd::RunAuditScan(nativeOpts, &nativeResult);
    if (!ok) {
        DWORD err = GetLastError();
        throw gcnew InvalidOperationException(
            String::Format("RunAuditScan falhou. Win32 error: {0}", err));
    }

    auto managed = gcnew ScanResultManaged();
    managed->ExecutablesScanned = nativeResult.executables_scanned;
    managed->DllsEvaluated      = nativeResult.dlls_evaluated;
    managed->PhantomCount       = nativeResult.phantom_count;
    managed->WritableDirCount   = nativeResult.writable_dir_count;
    managed->AclIssueCount      = nativeResult.acl_issue_count;
    managed->ScanStart          = FiletimeToDateTimeImpl(nativeResult.scan_start);
    managed->ScanEnd            = FiletimeToDateTimeImpl(nativeResult.scan_end);

    for (const auto& f : nativeResult.findings) {
        auto mf = gcnew AuditFindingManaged();
        mf->Severity       = static_cast<RiskLevelManaged>(f.severity);
        mf->TargetPath     = gcnew String(f.target_path);
        mf->DllName        = gcnew String(f.dll_name);
        mf->IssueCode      = gcnew String(f.issue_code);
        mf->Detail         = gcnew String(f.detail);
        mf->Recommendation = gcnew String(f.recommendation);
        managed->Findings->Add(mf);
    }

    return managed;
}

bool DhdBridgeFacade::WriteJsonReport(ScanResultManaged^ result, String^ outputPath)
{
    if (result == nullptr)  throw gcnew ArgumentNullException("result");
    if (String::IsNullOrWhiteSpace(outputPath))
        throw gcnew ArgumentNullException("outputPath");
    if (outputPath->Length >= MAX_PATH)
        throw gcnew ArgumentException("outputPath excede MAX_PATH");

    // Reconstruct native ScanResult from managed (findings already written by RunAuditScan)
    // We re-run WriteJsonReport via the path the scan already wrote, or rebuild.
    // Since WriteJsonReport operates on ScanResult which contains std::vector,
    // we rebuild a minimal native ScanResult for the report writer.
    dhd::ScanResult nativeResult;
    nativeResult.executables_scanned = result->ExecutablesScanned;
    nativeResult.dlls_evaluated      = result->DllsEvaluated;
    nativeResult.phantom_count       = result->PhantomCount;
    nativeResult.writable_dir_count  = result->WritableDirCount;
    nativeResult.acl_issue_count     = result->AclIssueCount;

    for each (AuditFindingManaged^ mf in result->Findings) {
        dhd::AuditFinding f = {};
        f.severity = static_cast<dhd::RiskLevel>(mf->Severity);
        MarshalString(mf->TargetPath,     f.target_path, _countof(f.target_path));
        MarshalString(mf->DllName,        f.dll_name,    _countof(f.dll_name));
        MarshalString(mf->IssueCode,      f.issue_code,  _countof(f.issue_code));
        MarshalString(mf->Detail,         f.detail,      _countof(f.detail));
        MarshalString(mf->Recommendation, f.recommendation, _countof(f.recommendation));
        nativeResult.findings.push_back(f);
    }

    wchar_t nativePath[MAX_PATH];
    if (!MarshalString(outputPath, nativePath, _countof(nativePath)))
        throw gcnew ArgumentException("outputPath inválido");

    return dhd::WriteJsonReport(nativeResult, nativePath) != FALSE;
}

// =============================================================================
// Runtime Monitor
// =============================================================================

bool DhdBridgeFacade::StartMonitor(Action<MonitorFindingManaged^>^ callback)
{
    // Release previous handles if any
    if (s_monitorCallbackHandleAllocated) {
        s_monitorCallbackHandle.Free();
        s_monitorCallbackHandleAllocated = false;
    }
    if (s_nativeDelegateAllocated) {
        s_nativeDelegateHandle.Free();
        s_nativeDelegate = nullptr;
        s_nativeDelegateAllocated = false;
    }

    dhd::MonitorCallback nativeCb = nullptr;

    if (callback != nullptr) {
        // Pin the user callback delegate
        s_monitorCallbackHandle = GCHandle::Alloc(callback);
        s_monitorCallbackHandleAllocated = true;

        // Create a native-callable thunk via GetFunctionPointerForDelegate
        s_nativeDelegate = gcnew MonitorNativeDelegate(
            &DhdBridgeFacade::MonitorNativeShim);
        s_nativeDelegateHandle = GCHandle::Alloc(s_nativeDelegate);
        s_nativeDelegateAllocated = true;
        IntPtr ptr = Marshal::GetFunctionPointerForDelegate(s_nativeDelegate);
        nativeCb = reinterpret_cast<dhd::MonitorCallback>(ptr.ToPointer());
    }

    BOOL ok = dhd::StartMonitor(nativeCb, nullptr);
    return ok != FALSE;
}

void DhdBridgeFacade::StopMonitor()
{
    dhd::StopMonitor();

    if (s_monitorCallbackHandleAllocated) {
        s_monitorCallbackHandle.Free();
        s_monitorCallbackHandleAllocated = false;
    }
    if (s_nativeDelegateAllocated) {
        s_nativeDelegateHandle.Free();
        s_nativeDelegate = nullptr;
        s_nativeDelegateAllocated = false;
    }
}

bool DhdBridgeFacade::IsMonitorRunning()
{
    return dhd::IsMonitorRunning() != FALSE;
}

void DhdBridgeFacade::ForcePollingSnapshot()
{
    dhd::ForcePollingSnapshot();
}

unsigned long long DhdBridgeFacade::GetFindingCount()
{
    return dhd::GetFindingCount();
}

// =============================================================================
// Logging Engine
// =============================================================================

bool DhdBridgeFacade::InitializeLogger(String^ logDir)
{
    if (String::IsNullOrWhiteSpace(logDir))
        throw gcnew ArgumentNullException("logDir");
    if (logDir->Length >= MAX_PATH)
        throw gcnew ArgumentException("logDir excede MAX_PATH");

    wchar_t nativeDir[MAX_PATH];
    if (!MarshalString(logDir, nativeDir, _countof(nativeDir)))
        throw gcnew ArgumentException("logDir inválido");

    return dhd::InitializeLoggingEngine(nativeDir) != FALSE;
}

void DhdBridgeFacade::ShutdownLogger()
{
    dhd::ShutdownLoggingEngine();
}

bool DhdBridgeFacade::IsLoggerInitialized()
{
    return dhd::IsLoggingEngineInitialized() != FALSE;
}

void DhdBridgeFacade::FlushLog()
{
    dhd::FlushLog();
}

unsigned long long DhdBridgeFacade::GetDroppedEventCount()
{
    return dhd::GetDroppedEventCount();
}

// =============================================================================
// Hardening
// =============================================================================

bool DhdBridgeFacade::HardenLogDirectory(String^ path)
{
    if (String::IsNullOrWhiteSpace(path)) throw gcnew ArgumentNullException("path");
    wchar_t buf[MAX_PATH];
    if (!MarshalString(path, buf, _countof(buf))) throw gcnew ArgumentException("path excede MAX_PATH");
    return dhd::HardenLogDirectory(buf) != FALSE;
}

bool DhdBridgeFacade::HardenPolicyFile(String^ path)
{
    if (String::IsNullOrWhiteSpace(path)) throw gcnew ArgumentNullException("path");
    wchar_t buf[MAX_PATH];
    if (!MarshalString(path, buf, _countof(buf))) throw gcnew ArgumentException("path excede MAX_PATH");
    return dhd::HardenPolicyFile(buf) != FALSE;
}

bool DhdBridgeFacade::VerifyHashDatabaseIntegrity(String^ dbPath)
{
    if (String::IsNullOrWhiteSpace(dbPath)) throw gcnew ArgumentNullException("dbPath");
    wchar_t buf[MAX_PATH];
    if (!MarshalString(dbPath, buf, _countof(buf))) throw gcnew ArgumentException("dbPath excede MAX_PATH");
    return dhd::VerifyHashDatabaseIntegrity(buf) != FALSE;
}

String^ DhdBridgeFacade::SnapshotFileHash(String^ filePath)
{
    if (String::IsNullOrWhiteSpace(filePath)) throw gcnew ArgumentNullException("filePath");
    wchar_t nativePath[MAX_PATH];
    if (!MarshalString(filePath, nativePath, _countof(nativePath)))
        throw gcnew ArgumentException("filePath excede MAX_PATH");

    // SHA256_HEX_LEN = 64 chars + NUL
    wchar_t hexBuf[65] = {};
    BOOL ok = dhd::SnapshotFileHash(nativePath, hexBuf, _countof(hexBuf));
    if (!ok) {
        DWORD err = GetLastError();
        throw gcnew InvalidOperationException(
            String::Format("SnapshotFileHash falhou. Win32 error: {0}", err));
    }
    return gcnew String(hexBuf);
}

bool DhdBridgeFacade::VerifyFileIntegrity(String^ filePath, String^ expectedHex)
{
    if (String::IsNullOrWhiteSpace(filePath))   throw gcnew ArgumentNullException("filePath");
    if (String::IsNullOrWhiteSpace(expectedHex)) throw gcnew ArgumentNullException("expectedHex");
    if (expectedHex->Length != 64)
        throw gcnew ArgumentException("expectedHex deve ter 64 caracteres (SHA-256 hex)");

    wchar_t nativePath[MAX_PATH];
    wchar_t nativeHex[65];
    if (!MarshalString(filePath,   nativePath, _countof(nativePath)))
        throw gcnew ArgumentException("filePath excede MAX_PATH");
    if (!MarshalString(expectedHex, nativeHex, _countof(nativeHex)))
        throw gcnew ArgumentException("expectedHex inválido");

    return dhd::VerifyFileIntegrity(nativePath, nativeHex) != FALSE;
}

} // namespace DhdBridge
