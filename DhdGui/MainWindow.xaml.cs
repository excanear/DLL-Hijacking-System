using DhdGui.Services;
using DhdGui.Views;
using Microsoft.Extensions.DependencyInjection;
using ModernWpf.Controls;
using System.Windows;

namespace DhdGui;

public partial class MainWindow : Window
{
    private readonly IServiceProvider _services;

    public MainWindow(IServiceProvider services)
    {
        InitializeComponent();
        _services = services;

        // V-08: use named handler so it can be cleanly unregistered on Unloaded
        Loaded   += MainWindow_Loaded;
        Unloaded += MainWindow_Unloaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        NavView.SelectedItem = NavView.MenuItems[0];
        Navigate("Dashboard");
    }

    private void MainWindow_Unloaded(object sender, RoutedEventArgs e)
    {
        Loaded   -= MainWindow_Loaded;
        Unloaded -= MainWindow_Unloaded;
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item && item.Tag is string tag)
            Navigate(tag);
    }

    private void Navigate(string tag)
    {
        System.Windows.Controls.Page? page = tag switch
        {
            "Dashboard" => (System.Windows.Controls.Page)_services.GetRequiredService<DashboardPage>(),
            "Monitor"   => _services.GetRequiredService<RealtimeMonitorPage>(),
            "Validate"  => _services.GetRequiredService<ValidateDllPage>(),
            "Audit"     => _services.GetRequiredService<AuditScannerPage>(),
            "Logs"      => _services.GetRequiredService<LogViewerPage>(),
            "Settings"  => _services.GetRequiredService<SettingsPage>(),
            _           => null
        };

        if (page is not null)
            ContentFrame.Navigate(page);
    }
}
