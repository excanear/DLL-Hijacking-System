using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class SettingsPage : Page
{
    public SettingsPage(SettingsViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
