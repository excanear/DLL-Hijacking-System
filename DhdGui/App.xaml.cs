using DhdGui.Services;
using DhdGui.ViewModels;
using DhdGui.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Windows;

namespace DhdGui;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Capture any unhandled exceptions and write to a crash log
        DispatcherUnhandledException += (s, ex) =>
        {
            var logPath = Path.Combine(AppContext.BaseDirectory, "crash.log");
            // V-12: append so crash history is never overwritten
            File.AppendAllText(logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [UI]\n{ex.Exception}\n\n");
            System.Windows.MessageBox.Show(ex.Exception.ToString(), "Crash", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            ex.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (s, ex) =>
        {
            var logPath = Path.Combine(AppContext.BaseDirectory, "crash.log");
            File.AppendAllText(logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [Fatal]\n{ex.ExceptionObject}\n\n");
        };

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices(services =>
            {
                // Services
                services.AddSingleton<IDhdService, DhdService>();
                services.AddSingleton<ILogFileReader, LogFileReader>();
                // NavigationService removed (V-08): MainWindow uses its own Navigate() method

                // ViewModels
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<DashboardViewModel>();    // Singleton: timer e log dir persistem
                services.AddSingleton<RealtimeMonitorViewModel>(); // Singleton: estado do monitor persiste
                services.AddTransient<ValidateDllViewModel>();
                services.AddTransient<AuditScannerViewModel>();
                services.AddSingleton<LogViewerViewModel>();    // Singleton: estado de filtros persiste
                services.AddTransient<SettingsViewModel>();

                // Pages (transient so each navigation gets a fresh page)
                services.AddTransient<DashboardPage>();
                services.AddTransient<RealtimeMonitorPage>();
                services.AddTransient<ValidateDllPage>();
                services.AddTransient<AuditScannerPage>();
                services.AddTransient<LogViewerPage>();
                services.AddTransient<SettingsPage>();

                // Main window
                services.AddSingleton<MainWindow>();
            })
            .Build();

        await _host.StartAsync();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        mainWindow.DataContext = _host.Services.GetRequiredService<MainViewModel>();
        mainWindow.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            var dhdService = _host.Services.GetRequiredService<IDhdService>();
            dhdService.Shutdown();
            await _host.StopAsync();
            _host.Dispose();
        }
        base.OnExit(e);
    }
}
