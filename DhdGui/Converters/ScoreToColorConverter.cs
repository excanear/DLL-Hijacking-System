using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DhdGui.Converters;

[ValueConversion(typeof(double), typeof(Brush))]
public sealed class ScoreToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is double d ? ScoreBrush(d) : Brushes.Gray;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();

    internal static Brush ScoreBrush(double score) => score switch
    {
        <= 0.30 => new SolidColorBrush(Color.FromRgb(0x2E, 0x86, 0x48)),  // dark green
        <= 0.60 => new SolidColorBrush(Color.FromRgb(0xD4, 0xA0, 0x17)),  // amber
        _       => new SolidColorBrush(Color.FromRgb(0xC0, 0x39, 0x2B)),  // dark red
    };
}
