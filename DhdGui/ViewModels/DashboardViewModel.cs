using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdGui.Models;
using DhdGui.Services;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Threading;

namespace DhdGui.ViewModels;

public partial class DashboardViewModel : ObservableObject, IDisposable
{
    private readonly IDhdService   _dhd;
    private readonly ILogFileReader _logReader;
    private readonly DispatcherTimer _timer;
    private string   _logDirectory = string.Empty;

    [ObservableProperty] private string  _systemStatus   = "Não Inicializado";
    [ObservableProperty] private string  _policyMode     = "—";
    [ObservableProperty] private string  _lastEventTime  = "—";
    [ObservableProperty] private ulong   _findingCount;
    [ObservableProperty] private ulong   _droppedEvents;
    [ObservableProperty] private int     _sessionValidations;
    [ObservableProperty] private int     _sessionBlocks;
    [ObservableProperty] private bool    _isSystemRunning;

    // Event feed — last 100
    public ObservableCollection<LogEventModel> RecentEvents { get; } = new();

    public DashboardViewModel(IDhdService dhd, ILogFileReader logReader)
    {
        _dhd       = dhd;
        _logReader = logReader;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _timer.Tick += OnTimerTick;

        // Auto-load log directory from saved appsettings.json
        var logDir = ReadSettingsValue("LogDirectory");
        if (!string.IsNullOrEmpty(logDir))
            SetLogDirectory(logDir);
    }

    public void SetLogDirectory(string dir)
    {
        _logDirectory = dir;
        _timer.Start();
    }

    public void StopTimer() => _timer.Stop();

    [RelayCommand]
    private async Task RefreshAsync()
    {
        FindingCount  = _dhd.GetFindingCount();
        DroppedEvents = _dhd.GetDroppedEventCount();
        IsSystemRunning = _dhd.IsInitialized;
        SystemStatus = _dhd.IsInitialized ? "Inicializado" : "Parado";

        await LoadRecentEventsAsync();
    }

    [RelayCommand]
    private void StartSystem()
    {
        if (_dhd.IsInitialized)
        {
            SystemStatus = "Sistema já está inicializado.";
            return;
        }

        var policy  = ReadSettingsValue("PolicyFilePath");
        var hashDb  = ReadSettingsValue("HashDbPath");
        var logDir  = ReadSettingsValue("LogDirectory");
        var pollStr = ReadSettingsValue("PollIntervalMs");
        int poll    = int.TryParse(pollStr, out var p) ? p : 2000;

        if (string.IsNullOrWhiteSpace(policy) || string.IsNullOrWhiteSpace(hashDb) || string.IsNullOrWhiteSpace(logDir))
        {
            SystemStatus = "Configure os caminhos em Configurações antes de inicializar.";
            return;
        }

        bool ok = _dhd.Initialize(policy, hashDb, logDir, poll);
        IsSystemRunning = ok;
        SystemStatus    = ok ? "Inicializado" : "Falha na inicialização — veja crash.log";

        if (ok)
        {
            SetLogDirectory(logDir);
            _ = RefreshAsync();
        }
    }

    [RelayCommand]
    private void StopSystem()
    {
        _dhd.Shutdown();
        IsSystemRunning = false;
        SystemStatus = "Parado";
    }

    [RelayCommand]
    private void FlushLog() => _dhd.FlushLog();

    private async Task LoadRecentEventsAsync()
    {
        if (string.IsNullOrEmpty(_logDirectory)) return;

        var files = _logReader.GetAvailableLogFiles(_logDirectory);
        if (files.Count == 0) return;

        try
        {
            var events = await _logReader.ReadLogFileAsync(files[0]);
            var latest = events.TakeLast(100).Reverse().ToList();

            RecentEvents.Clear();
            foreach (var e in latest)
                RecentEvents.Add(e);

            if (latest.Count > 0)
                LastEventTime = latest[0].Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        }
        catch (Exception ex)
        {
            // V-04: log instead of silently swallowing — log dir may not exist yet on first launch
            System.Diagnostics.Debug.WriteLine($"[DashboardViewModel] LoadRecentEventsAsync error: {ex}");
        }
    }

    private static string ReadSettingsValue(string key)
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            if (!File.Exists(path)) return string.Empty;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty(key, out var el) ? el.GetString() ?? string.Empty : string.Empty;
        }
        catch { return string.Empty; }
    }

    private async void OnTimerTick(object? sender, EventArgs e) => await RefreshAsync();

    // V-01: stop the timer so it cannot fire after navigation away
    public void Dispose()
    {
        _timer.Stop();
        _timer.Tick -= OnTimerTick;
    }
}
