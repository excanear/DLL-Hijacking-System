using DhdGui.ViewModels;
using System.Windows.Controls;

namespace DhdGui.Views;

public partial class ValidateDllPage : Page
{
    public ValidateDllPage(ValidateDllViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
