using DhdBridge;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DhdGui.Converters;

[ValueConversion(typeof(LogSeverityManaged), typeof(Brush))]
public sealed class SeverityToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is LogSeverityManaged s ? SeverityBrush(s) : Brushes.Gray;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();

    internal static Brush SeverityBrush(LogSeverityManaged s) => s switch
    {
        LogSeverityManaged.Info    => Brushes.SeaGreen,
        LogSeverityManaged.Warning => Brushes.Goldenrod,
        LogSeverityManaged.Alert   => Brushes.OrangeRed,
        _                          => Brushes.Gray,
    };
}
