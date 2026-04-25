using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdBridge;
using DhdGui.Models;
using DhdGui.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;

namespace DhdGui.ViewModels;

public partial class AuditScannerViewModel : ObservableObject
{
    private readonly IDhdService _dhd;
    private CancellationTokenSource? _cts;

    [ObservableProperty] private bool   _isDirectory        = true;
    [ObservableProperty] private string _targetExe          = string.Empty;
    [ObservableProperty] private string _targetDirectory    = string.Empty;
    [ObservableProperty] private string _outputReportPath   = string.Empty;
    [ObservableProperty] private bool   _checkPhantomDlls   = true;
    [ObservableProperty] private bool   _checkWritableDirs  = true;
    [ObservableProperty] private bool   _checkAclPermissiveness = true;
    [ObservableProperty] private bool   _checkSearchOrder   = true;
    [ObservableProperty] private bool   _includeLowSeverity = false;
    [ObservableProperty] private int    _maxRecursionDepth  = 3;
    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private bool   _hasResults;
    [ObservableProperty] private string _statusText         = string.Empty;
    [ObservableProperty] private ScanSummary? _summary;

    // Filtered view
    [ObservableProperty] private RiskLevelManaged? _filterSeverity;
    [ObservableProperty] private string _filterIssueCode = string.Empty;

    private List<AuditFindingModel> _allFindings = new();
    public ObservableCollection<AuditFindingModel> Findings { get; } = new();

    public IEnumerable<RiskLevelManaged?> SeverityFilters { get; } =
        new RiskLevelManaged?[] { null }
        .Concat(Enum.GetValues<RiskLevelManaged>().Cast<RiskLevelManaged?>());

    public AuditScannerViewModel(IDhdService dhd) => _dhd = dhd;

    /// <summary>Proxy property: shows TargetDirectory or TargetExe depending on scan mode.</summary>
    public string TargetPath
    {
        get => IsDirectory ? TargetDirectory : TargetExe;
        set { if (IsDirectory) TargetDirectory = value; else TargetExe = value; }
    }

    public string TargetPlaceholder => IsDirectory ? "Diretório alvo…" : "Executável alvo (.exe)…";

    partial void OnIsDirectoryChanged(bool value)       { OnPropertyChanged(nameof(TargetPath)); OnPropertyChanged(nameof(TargetPlaceholder)); }
    partial void OnTargetDirectoryChanged(string value) => OnPropertyChanged(nameof(TargetPath));
    partial void OnTargetExeChanged(string value)       => OnPropertyChanged(nameof(TargetPath));

    [RelayCommand]
    private void BrowseTarget()
    {
        if (IsDirectory)
        {
            using var dialog = new System.Windows.Forms.FolderBrowserDialog
            {
                Description = "Selecionar diretório para audit"
            };
            if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                TargetDirectory = dialog.SelectedPath;
        }
        else
        {
            var dialog = new OpenFileDialog
            {
                Title  = "Selecionar executável",
                Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            };
            if (dialog.ShowDialog() == true)
                TargetExe = dialog.FileName;
        }
    }

    [RelayCommand]
    private void BrowseOutputReport()
    {
        var dialog = new SaveFileDialog
        {
            Title       = "Salvar relatório JSON",
            Filter      = "JSON files (*.json)|*.json",
            DefaultExt  = ".json",
            FileName    = $"audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.json",
        };
        if (dialog.ShowDialog() == true)
            OutputReportPath = dialog.FileName;
    }

    [RelayCommand]
    private async Task StartScanAsync()
    {
        IsBusy     = true;
        HasResults = false;
        StatusText = "Scanning…";
        _allFindings.Clear();
        Findings.Clear();

        var cts = new CancellationTokenSource();
        _cts = cts;
        try
        {
            var targetPath = IsDirectory ? TargetDirectory : TargetExe;
            if (string.IsNullOrWhiteSpace(targetPath) || !Path.Exists(targetPath))
            {
                StatusText = "Caminho não encontrado.";
                return;
            }

            var options = new ScanOptionsModel(
                IsDirectory ? null : TargetExe,
                IsDirectory ? TargetDirectory : null,
                CheckPhantomDlls,
                CheckWritableDirs,
                CheckAclPermissiveness,
                CheckSearchOrder,
                IncludeLowSeverity,
                MaxRecursionDepth,
                string.IsNullOrWhiteSpace(OutputReportPath) ? null : OutputReportPath);

            var (findings, summary) = await _dhd.RunAuditScanAsync(options, _cts.Token);
            _allFindings = findings;
            Summary      = summary;

            ApplyFilters();
            HasResults = true;
            StatusText = $"Scan concluído: {findings.Count} finding(s) em {(summary.ScanEnd - summary.ScanStart).TotalSeconds:F1}s";

            if (!string.IsNullOrWhiteSpace(OutputReportPath))
                _dhd.WriteJsonReport(findings, summary, OutputReportPath);
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelado.";
        }
        catch (Exception ex)
        {
            StatusText = $"Erro: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _cts = null;
            cts.Dispose();
        }
    }

    [RelayCommand]
    private void CancelScan() => _cts?.Cancel();

    [RelayCommand]
    private void ExportJson()
    {
        if (string.IsNullOrWhiteSpace(OutputReportPath) || Summary is null) return;
        _dhd.WriteJsonReport(_allFindings, Summary, OutputReportPath);
    }

    [RelayCommand]
    private void OpenReport()
    {
        if (File.Exists(OutputReportPath))
            Process.Start(new ProcessStartInfo(OutputReportPath) { UseShellExecute = true });
    }

    partial void OnFilterSeverityChanged(RiskLevelManaged? value)  => ApplyFilters();
    partial void OnFilterIssueCodeChanged(string value)            => ApplyFilters();

    private void ApplyFilters()
    {
        var filtered = _allFindings.AsEnumerable();

        if (FilterSeverity.HasValue)
            filtered = filtered.Where(f => f.Severity == FilterSeverity.Value);

        if (!string.IsNullOrWhiteSpace(FilterIssueCode))
            filtered = filtered.Where(f => f.IssueCode.Contains(FilterIssueCode, StringComparison.OrdinalIgnoreCase));

        Findings.Clear();
        foreach (var f in filtered) Findings.Add(f);
    }
}
