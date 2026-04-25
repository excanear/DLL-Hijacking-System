using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class DashboardPage : Page
{
    public DashboardPage(DashboardViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
