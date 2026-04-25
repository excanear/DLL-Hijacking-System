using System.Windows.Controls;

namespace DhdGui.Services;

public interface INavigationService
{
    void Navigate(string tag);
    Frame? Frame { get; set; }
}
