using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdBridge;
using DhdGui.Models;
using DhdGui.Services;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using Microsoft.Win32;
using SkiaSharp;
using System.IO;
using System.Linq;

namespace DhdGui.ViewModels;

public partial class ValidateDllViewModel : ObservableObject
{
    private readonly IDhdService _dhd;

    [ObservableProperty] private string  _dllPath     = string.Empty;
    [ObservableProperty] private bool    _isBusy;
    [ObservableProperty] private bool    _hasResult;
    [ObservableProperty] private ValidationResultModel? _result;
    [ObservableProperty] private string? _errorMessage;

    // Score breakdown for bar chart
    public ISeries[] ScoreSeries { get; private set; } = Array.Empty<ISeries>();

    public Axis[] ScoreYAxes { get; } = new[]
    {
        new Axis
        {
            Labels         = new[] { "Path ×0.40", "Nome ×0.15", "Hash ×0.25", "Assinatura ×0.20" },
            TextSize       = 11,
            MinLimit       = -0.5,
            MaxLimit       = 3.5,
        }
    };

    public ValidateDllViewModel(IDhdService dhd) => _dhd = dhd;

    [RelayCommand]
    private void BrowseDll()
    {
        var dialog = new OpenFileDialog
        {
            Title  = "Selecionar DLL",
            Filter = "DLL files (*.dll)|*.dll|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog() == true)
            DllPath = dialog.FileName;
    }

    [RelayCommand]
    private async Task ValidateAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(DllPath)) return;

        if (!File.Exists(DllPath))
        {
            ErrorMessage = "Arquivo não encontrado.";
            return;
        }

        if (Path.GetExtension(DllPath).ToLowerInvariant() != ".dll")
        {
            ErrorMessage = "O arquivo selecionado não é uma DLL.";
            return;
        }

        if (DllPath.Length > 260)
        {
            ErrorMessage = "Caminho excede MAX_PATH (260 caracteres).";
            return;
        }

        IsBusy    = true;
        HasResult = false;
        ErrorMessage = null;

        try
        {
            var r = await _dhd.ValidateDllAsync(DllPath, ct);
            Result    = r;
            HasResult = true;
            BuildChart(r);
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = "Validação cancelada.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Erro: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void BuildChart(ValidationResultModel r)
    {
        static SKColor ColorFor(double score) => score switch
        {
            <= 0.30 => SKColors.SeaGreen,
            <= 0.60 => SKColors.Goldenrod,
            _       => SKColors.OrangeRed,
        };

        var values = new[]
        {
            r.PathScore      * 0.40,
            r.NameScore      * 0.15,
            r.HashScore      * 0.25,
            r.SignatureScore  * 0.20,
        };

        ScoreSeries = values.Select((v, i) =>
            (ISeries)new RowSeries<double>
            {
                Values      = new[] { v },
                Name        = i switch { 0 => "Path", 1 => "Nome", 2 => "Hash", _ => "Assinatura" },
                Fill        = new SolidColorPaint(ColorFor(v)),
                MaxBarWidth = 28,
            }).ToArray();

        OnPropertyChanged(nameof(ScoreSeries));
    }
}
