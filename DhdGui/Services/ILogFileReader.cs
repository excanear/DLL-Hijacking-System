using DhdGui.Models;

namespace DhdGui.Services;

public interface ILogFileReader
{
    IReadOnlyList<string> GetAvailableLogFiles(string logDirectory);
    Task<List<LogEventModel>> ReadLogFileAsync(string filePath, CancellationToken ct = default);
}
