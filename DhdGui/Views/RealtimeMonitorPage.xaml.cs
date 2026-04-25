using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class RealtimeMonitorPage : Page
{
    public RealtimeMonitorPage(RealtimeMonitorViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
