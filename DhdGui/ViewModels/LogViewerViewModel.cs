using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdBridge;
using DhdGui.Models;
using DhdGui.Services;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;

namespace DhdGui.ViewModels;

public partial class LogViewerViewModel : ObservableObject
{
    private readonly ILogFileReader _reader;
    private readonly IDhdService    _dhd;

    [ObservableProperty] private string   _logDirectory = string.Empty;
    [ObservableProperty] private string?  _selectedFile;
    [ObservableProperty] private bool     _isBusy;
    [ObservableProperty] private string   _searchText     = string.Empty;
    [ObservableProperty] private LogSeverityManaged? _filterSeverity;
    [ObservableProperty] private string   _filterSource   = string.Empty;
    [ObservableProperty] private DateTime _filterFrom     = DateTime.Today.AddDays(-7);
    [ObservableProperty] private DateTime _filterTo       = DateTime.Today.AddDays(1);

    public IReadOnlyList<string> AvailableFiles { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> AvailableFileNames { get; private set; } = Array.Empty<string>();
    private List<LogEventModel> _allEvents = new();
    public ObservableCollection<LogEventModel> FilteredEvents { get; } = new();

    // SelectedFileName tracks the display name; SelectedFile holds the full path
    private string? _selectedFileName;
    private bool _settingFileFromName; // V-07: guard against double-load
    public string? SelectedFileName
    {
        get => _selectedFileName;
        set
        {
            if (_selectedFileName == value) return;
            _selectedFileName = value;
            OnPropertyChanged();
            // Resolve full path without triggering double load
            _settingFileFromName = true;
            try
            {
                if (value is not null)
                {
                    var names = AvailableFileNames as IList<string> ?? AvailableFileNames.ToList();
                    var idx = names.IndexOf(value);
                    if (idx >= 0 && idx < AvailableFiles.Count)
                        SelectedFile = AvailableFiles[idx];
                }
            }
            finally
            {
                _settingFileFromName = false;
            }
        }
    }

    public IEnumerable<LogSeverityManaged?> SeverityFilters { get; } =
        new LogSeverityManaged?[] { null }
        .Concat(Enum.GetValues<LogSeverityManaged>().Cast<LogSeverityManaged?>());

    public LogViewerViewModel(ILogFileReader reader, IDhdService dhd)
    {
        _reader = reader;
        _dhd    = dhd;

        // Auto-load log directory from saved appsettings.json
        var logDir = ReadSettingsValue("LogDirectory");
        if (!string.IsNullOrEmpty(logDir))
            SetLogDirectory(logDir);
    }

    public void SetLogDirectory(string dir)
    {
        LogDirectory = dir;
        RefreshFileList();
    }

    [RelayCommand]
    private void RefreshFileList()
    {
        AvailableFiles      = _reader.GetAvailableLogFiles(LogDirectory);
        AvailableFileNames  = AvailableFiles.Select(Path.GetFileName).ToList()!;
        OnPropertyChanged(nameof(AvailableFiles));
        OnPropertyChanged(nameof(AvailableFileNames));

        if (AvailableFiles.Count > 0 && SelectedFile is null)
        {
            SelectedFile     = AvailableFiles[0];
            SelectedFileName = AvailableFileNames[0];
        }
    }

    [RelayCommand]
    private async Task LoadFileAsync()
    {
        if (SelectedFile is null) return;
        IsBusy = true;
        try
        {
            _allEvents = await _reader.ReadLogFileAsync(SelectedFile);
            ApplyFilters();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"LogViewer load error: {ex.Message}");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private void FlushLog() => _dhd.FlushLog();

    partial void OnSelectedFileChanged(string? value)
    {
        if (!_settingFileFromName) // V-07: skip if triggered by SelectedFileName setter
            LoadFileAsyncSafe();
    }

    // V-11: wrapper so unhandled exceptions in the fire-and-forget are always logged
    private async void LoadFileAsyncSafe()
    {
        try { await LoadFileAsync(); }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[LogViewerViewModel] LoadFileAsync unhandled: {ex}");
        }
    }
    partial void OnSearchTextChanged(string value)      => ApplyFilters();
    partial void OnFilterSeverityChanged(LogSeverityManaged? value) => ApplyFilters();
    partial void OnFilterSourceChanged(string value)    => ApplyFilters();
    partial void OnFilterFromChanged(DateTime value)    => ApplyFilters();
    partial void OnFilterToChanged(DateTime value)      => ApplyFilters();

    private void ApplyFilters()
    {
        var filtered = _allEvents.AsEnumerable();

        if (FilterSeverity.HasValue)
            filtered = filtered.Where(e => e.Severity == FilterSeverity.Value);

        if (!string.IsNullOrWhiteSpace(FilterSource))
            filtered = filtered.Where(e => e.SourceModule.Contains(FilterSource, StringComparison.OrdinalIgnoreCase));

        filtered = filtered.Where(e => e.Timestamp >= FilterFrom && e.Timestamp <= FilterTo);

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var q = SearchText;
            filtered = filtered.Where(e =>
                e.DllPath.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                e.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                e.SourceModule.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        FilteredEvents.Clear();
        foreach (var e in filtered)
            FilteredEvents.Add(e);
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
}
