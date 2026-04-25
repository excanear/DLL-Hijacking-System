using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DhdGui.Services;
using DhdGui.Views;
using Microsoft.Extensions.DependencyInjection;

namespace DhdGui.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IDhdService _dhd;

    [ObservableProperty] private bool _isSystemInitialized;
    [ObservableProperty] private string _systemStatus = "Não Inicializado";

    public MainViewModel(IDhdService dhd)
    {
        _dhd = dhd;
    }

    [RelayCommand]
    public void InitializeSystem(string args)
    {
        // Called with "policyPath|hashDbPath|logDir|pollMs" from SettingsViewModel
        var parts = args.Split('|');
        if (parts.Length < 4) return;

        bool ok = _dhd.Initialize(parts[0], parts[1], parts[2],
            int.TryParse(parts[3], out int ms) ? ms : 2000);

        IsSystemInitialized = ok;
        SystemStatus = ok ? "Inicializado" : "Erro ao Inicializar";
    }

    [RelayCommand]
    public void ShutdownSystem()
    {
        _dhd.Shutdown();
        IsSystemInitialized = false;
        SystemStatus = "Parado";
    }
}
