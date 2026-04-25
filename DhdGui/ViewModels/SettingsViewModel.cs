using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdGui.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;

namespace DhdGui.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IDhdService _dhd;
    private readonly IServiceProvider _services;
    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    [ObservableProperty] private string _policyFilePath = string.Empty;
    [ObservableProperty] private string _hashDbPath     = string.Empty;
    [ObservableProperty] private string _logDirectory   = string.Empty;
    [ObservableProperty] private int    _pollIntervalMs = 2000;
    // _monitorEnabled removed (V-05: was declared but never bound to UI or logic)

    [ObservableProperty] private string _statusMessage  = string.Empty;
    [ObservableProperty] private string _hashDbIntegrityBadge = string.Empty;
    [ObservableProperty] private bool   _hashDbIntegrityOk = false;  // A-12: track integrity status for color binding
    [ObservableProperty] private string _snapshotHashResult   = string.Empty;
    [ObservableProperty] private string _bootstrapOutput      = string.Empty;

    public SettingsViewModel(IDhdService dhd, IServiceProvider services)
    {
        _dhd      = dhd;
        _services = services;
        LoadSettings();
    }

    // ── Paths ────────────────────────────────────────────────────────────────

    [RelayCommand] private void BrowsePolicyFile()
    {
        if (Browse("Policy files (*.json)|*.json", out var path))
            PolicyFilePath = path;
    }

    [RelayCommand] private void BrowseHashDb()
    {
        if (Browse("JSON files (*.json)|*.json", out var path))
            HashDbPath = path;
    }

    [RelayCommand] private void BrowseLogDirectory()
    {
        using var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Log directory" };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            LogDirectory = dlg.SelectedPath;
    }

    [RelayCommand]
    private void ReloadPolicy()
    {
        if (!ValidatePaths(out var msg)) { StatusMessage = msg; return; }
        bool ok = _dhd.Initialize(PolicyFilePath, HashDbPath, LogDirectory, PollIntervalMs);
        StatusMessage = ok ? "Política recarregada." : "Falha ao recarregar política."; 
    }

    [RelayCommand]
    private void VerifyHashDb()
    {
        if (string.IsNullOrWhiteSpace(HashDbPath)) { StatusMessage = "Configure o Hash Database antes de verificar."; return; }
        bool ok = _dhd.VerifyHashDatabaseIntegrity(HashDbPath);
        HashDbIntegrityOk = ok;  // A-12: update color binding flag
        HashDbIntegrityBadge = ok ? "✔ Íntegro" : "✘ Falha de integridade";
    }

    // ── Hardening ────────────────────────────────────────────────────────────

    [RelayCommand]
    private void HardenLogDir()
    {
        if (string.IsNullOrWhiteSpace(LogDirectory)) { StatusMessage = "Configure o Log Directory antes de aplicar hardening."; return; }
        bool ok = _dhd.HardenLogDirectory(LogDirectory);
        StatusMessage = ok ? "ACL do Log Dir aplicada." : "Falha ao restringir ACL do Log Dir.";
    }

    [RelayCommand]
    private void HardenPolicyFile()
    {
        if (string.IsNullOrWhiteSpace(PolicyFilePath)) { StatusMessage = "Configure o Policy File antes de aplicar hardening."; return; }
        bool ok = _dhd.HardenPolicyFile(PolicyFilePath);
        StatusMessage = ok ? "ACL do Policy File aplicada." : "Falha ao restringir ACL do Policy File.";
    }

    [RelayCommand]
    private void SnapshotHash()
    {
        if (string.IsNullOrWhiteSpace(PolicyFilePath)) { StatusMessage = "Configure o Policy File antes de calcular snapshot."; return; }
        var hash = _dhd.SnapshotFileHash(PolicyFilePath);
        SnapshotHashResult = hash ?? "Falha ao calcular hash.";
    }

    // ── Bootstrap ────────────────────────────────────────────────────────────

    [RelayCommand]
    private async Task RunBootstrapAsync()
    {
        var exePath = Path.Combine(AppContext.BaseDirectory, "bootstrap_hashdb.exe");
        if (!File.Exists(exePath))
        {
            BootstrapOutput = $"bootstrap_hashdb.exe não encontrado em:\n{exePath}";
            return;
        }

        BootstrapOutput = "Iniciando bootstrap…\n";
        try
        {
            var psi = new ProcessStartInfo(exePath)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };

            // V-19: Process.Start can return null — never use ! operator here
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                BootstrapOutput = "Falha ao iniciar bootstrap_hashdb.exe (Process.Start retornou null).";
                return;
            }

            // Read stdout and stderr concurrently to avoid deadlock (A-08)
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            await Task.WhenAll(stdoutTask, stderrTask);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            await proc.WaitForExitAsync();

            BootstrapOutput = stdout + (string.IsNullOrEmpty(stderr) ? "" : "\n[STDERR]\n" + stderr);
        }
        catch (Exception ex)
        {
            BootstrapOutput = $"Erro: {ex.Message}";
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    [RelayCommand]
    private void SaveSettings()
    {
        // V-14: validate before writing — prevents persisting invalid config to disk
        if (!ValidatePaths(out var msg)) { StatusMessage = msg; return; }

        var cfg = new AppSettings
        {
            PolicyFilePath = PolicyFilePath,
            HashDbPath     = HashDbPath,
            LogDirectory   = LogDirectory,
            PollIntervalMs = PollIntervalMs,
        };

        try
        {
            var json = JsonSerializer.Serialize(cfg, AppSettingsJsonContext.Default.AppSettings);
            File.WriteAllText(SettingsPath, json);
            StatusMessage = "Configurações salvas.";
        }
        catch (IOException ex)
        {
            StatusMessage = $"⚠ Erro ao salvar configurações: {ex.Message}";
            Debug.WriteLine($"[SettingsViewModel] SaveSettings failed: {ex}");
        }
    }

    [RelayCommand]
    private void ApplyAndInit()
    {
        if (!ValidatePaths(out var msg)) { StatusMessage = msg; return; }
        SaveSettings();
        bool ok = _dhd.Initialize(PolicyFilePath, HashDbPath, LogDirectory, PollIntervalMs);
        StatusMessage = ok ? "Sistema inicializado." : "Falha na inicialização.";

        if (ok)
        {
            // V-09: propagate LogDirectory to Singleton VMs that own the log state
            _services.GetRequiredService<DashboardViewModel>().SetLogDirectory(LogDirectory);
            _services.GetRequiredService<LogViewerViewModel>().SetLogDirectory(LogDirectory);
        }
    }

    private void LoadSettings()
    {
        if (!File.Exists(SettingsPath)) return;
        try
        {
            var json = File.ReadAllText(SettingsPath);
            var cfg  = JsonSerializer.Deserialize(json, AppSettingsJsonContext.Default.AppSettings);
            if (cfg is null) return;
            PolicyFilePath = cfg.PolicyFilePath;
            HashDbPath     = cfg.HashDbPath;
            LogDirectory   = cfg.LogDirectory;
            PollIntervalMs = cfg.PollIntervalMs;
        }
        catch (Exception ex) { Debug.WriteLine($"[SettingsViewModel] LoadSettings failed: {ex.Message}"); }
    }

    private static bool Browse(string filter, out string path)
    {
        var dlg = new OpenFileDialog { Filter = filter };
        if (dlg.ShowDialog() == true) { path = dlg.FileName; return true; }
        path = string.Empty;
        return false;
    }

    private bool ValidatePaths(out string message)
    {
        if (string.IsNullOrWhiteSpace(PolicyFilePath))
            { message = "⚠ Configure o caminho do Policy File."; return false; }
        if (string.IsNullOrWhiteSpace(HashDbPath))
            { message = "⚠ Configure o caminho do Hash Database."; return false; }
        if (string.IsNullOrWhiteSpace(LogDirectory))
            { message = "⚠ Configure o Log Directory."; return false; }
        message = string.Empty;
        return true;
    }
}

// ── Settings model ────────────────────────────────────────────────────────────

public class AppSettings
{
    public string PolicyFilePath { get; set; } = string.Empty;
    public string HashDbPath     { get; set; } = string.Empty;
    public string LogDirectory   { get; set; } = string.Empty;
    public int    PollIntervalMs { get; set; } = 2000;
}

[JsonSerializable(typeof(AppSettings))]
internal partial class AppSettingsJsonContext : JsonSerializerContext { }
