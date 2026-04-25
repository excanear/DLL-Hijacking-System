using DhdBridge;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DhdGui.Converters;

[ValueConversion(typeof(RiskLevelManaged), typeof(Brush))]
public sealed class RiskLevelToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is RiskLevelManaged r ? RiskBrush(r) : Brushes.Gray;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();

    internal static Brush RiskBrush(RiskLevelManaged r) => r switch
    {
        RiskLevelManaged.Low      => Brushes.SeaGreen,
        RiskLevelManaged.Medium   => Brushes.Goldenrod,
        RiskLevelManaged.High     => Brushes.OrangeRed,
        RiskLevelManaged.Critical => Brushes.Red,
        _                         => Brushes.Gray,
    };
}
