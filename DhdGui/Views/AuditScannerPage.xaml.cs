using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class AuditScannerPage : Page
{
    public AuditScannerPage(AuditScannerViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
