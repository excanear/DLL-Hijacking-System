using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdGui.Models;
using DhdGui.Services;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;

namespace DhdGui.ViewModels;

public partial class RealtimeMonitorViewModel : ObservableObject, IDisposable
{
    private readonly IDhdService  _dhd;
    private readonly DispatcherTimer _minuteTimer;
    private readonly Queue<ObservableValue> _chartValues = new();
    private readonly object _chartLock = new(); // V-15: synchronize queue access
    private int _currentMinuteCount;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartMonitorCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopMonitorCommand))]
    [NotifyCanExecuteChangedFor(nameof(ForceSnapshotCommand))]
    private bool _isRunning;

    [ObservableProperty] private bool _hasFindings;
    [ObservableProperty] private string _statusText = string.Empty;

    public ObservableCollection<MonitorFindingModel> Findings { get; } = new();

    public ISeries[] ChartSeries { get; }
    private readonly ObservableCollection<ObservableValue> _seriesValues = new();

    public RealtimeMonitorViewModel(IDhdService dhd)
    {
        _dhd = dhd;

        ChartSeries = new ISeries[]
        {
            new LineSeries<ObservableValue>
            {
                Values    = _seriesValues,
                Fill      = null,
                Stroke    = new SolidColorPaint(SKColors.OrangeRed, 2),
                GeometrySize  = 4,
                GeometryStroke = new SolidColorPaint(SKColors.OrangeRed, 2),
                Name      = "Findings/min",
            }
        };

        // Seed 60 zero points
        for (int i = 0; i < 60; i++)
        {
            var v = new ObservableValue(0);
            _seriesValues.Add(v);
            _chartValues.Enqueue(v);
        }

        _minuteTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
        _minuteTimer.Tick += OnMinuteTick;

        // Sync state with bridge on construction (VM is Transient — bridge may already be running)
        _isRunning = _dhd.IsMonitorRunning;
        StatusText = _isRunning ? "Monitor em execução." : string.Empty;
    }

    private void OnMinuteTick(object? sender, EventArgs e)
    {
        // V-18: guard Application.Current null (test context or shutdown)
        if (Application.Current is null) return;

        Application.Current.Dispatcher.InvokeAsync(() =>
        {
            lock (_chartLock) // V-15: thread-safe queue access
            {
                var old = _chartValues.Dequeue();
                old.Value = 0;

                var v = new ObservableValue(_currentMinuteCount);
                _seriesValues.RemoveAt(0);
                _seriesValues.Add(v);
                _chartValues.Enqueue(v);
                _currentMinuteCount = 0;
            }
        });
    }

    [RelayCommand(CanExecute = nameof(CanStartMonitor))]
    private void StartMonitor()
    {
        if (IsRunning) return;

        if (!_dhd.IsInitialized)
        {
            StatusText = "⚠ Sistema não inicializado. Configure os caminhos em Configurações primeiro.";
            return;
        }

        bool ok = _dhd.StartMonitor(finding =>
        {
            // V-18: guard Application.Current null
            if (Application.Current is null) return;

            Application.Current.Dispatcher.InvokeAsync(() =>
            {
                Findings.Insert(0, finding);
                lock (_chartLock) // V-15: protect counter
                    _currentMinuteCount++;
                HasFindings = true;
            });
        });

        if (ok)
        {
            IsRunning = true;
            _minuteTimer.Start();
            StatusText = "Monitor em execução.";
        }
        else
        {
            StatusText = "Falha ao iniciar o monitor — verifique crash.log.";
        }
    }
    private bool CanStartMonitor() => !IsRunning;

    [RelayCommand(CanExecute = nameof(CanStopMonitor))]
    private void StopMonitor()
    {
        _dhd.StopMonitor();
        IsRunning = false;
        _minuteTimer.Stop();
        StatusText = "Monitor parado.";
    }
    private bool CanStopMonitor() => IsRunning;

    [RelayCommand(CanExecute = nameof(CanForceSnapshot))]
    private void ForceSnapshot()
    {
        DhdBridge.DhdBridgeFacade.ForcePollingSnapshot();
        StatusText = "Snapshot forçado.";
    }
    private bool CanForceSnapshot() => IsRunning;

    [RelayCommand]
    private void ClearFindings()
    {
        Findings.Clear();
        HasFindings = false;
    }

    // V-03: stop timer and unregister tick so no callbacks fire after disposal
    public void Dispose()
    {
        _minuteTimer.Stop();
        _minuteTimer.Tick -= OnMinuteTick;
    }
}
