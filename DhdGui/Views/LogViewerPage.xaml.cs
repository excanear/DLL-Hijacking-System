using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class LogViewerPage : Page
{
    public LogViewerPage(LogViewerViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
