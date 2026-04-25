using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace DhdGui.Converters;

/// <summary>Converts bool to one of two strings (TrueValue / FalseValue).</summary>
public sealed class BoolToStringConverter : IValueConverter
{
    public string TrueValue  { get; set; } = "True";
    public string FalseValue { get; set; } = "False";

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is bool b && b ? TrueValue : FalseValue;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Converts bool to one of two named Brushes.</summary>
public sealed class BoolToColorConverter : IValueConverter
{
    // V-16: static shared instance avoids creating a new BrushConverter on every binding evaluation
    private static readonly BrushConverter _brushConverter = new();

    public string TrueColor  { get; set; } = "SeaGreen";
    public string FalseColor { get; set; } = "OrangeRed";

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var name = value is bool b && b ? TrueColor : FalseColor;
        try
        {
            // V-21: catch invalid color strings (e.g. typos in XAML) instead of crashing
            return _brushConverter.ConvertFromString(name) ?? Brushes.Gray;
        }
        catch
        {
            return Brushes.Gray;
        }
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Inverts a bool value.</summary>
public sealed class InvertBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is bool b ? !b : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is bool b ? !b : value;
}

/// <summary>Converts null or empty string to Collapsed, non-empty to Visible.</summary>
public sealed class NullOrEmptyToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrEmpty(value as string)
            ? System.Windows.Visibility.Collapsed
            : System.Windows.Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Returns only the file name portion of a full path string.</summary>
public sealed class FileNameConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is string s ? System.IO.Path.GetFileName(s) : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
