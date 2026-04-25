using DhdBridge;
using DhdGui.Models;
using System.IO;
using System.Text.Json;

namespace DhdGui.Services;

public sealed class LogFileReader : ILogFileReader
{
    public IReadOnlyList<string> GetAvailableLogFiles(string logDirectory)
    {
        if (!Directory.Exists(logDirectory))
            return Array.Empty<string>();

        return Directory.GetFiles(logDirectory, "*.jsonl", SearchOption.TopDirectoryOnly)
            .OrderByDescending(f => f)
            .ToArray();
    }

    public async Task<List<LogEventModel>> ReadLogFileAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            return new List<LogEventModel>();

        var result = new List<LogEventModel>();

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);

        while (!reader.EndOfStream)
        {
            ct.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(ct);
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var model = ParseLine(line);
            if (model is not null)
                result.Add(model);
        }

        return result;
    }

    private static LogEventModel? ParseLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            // Parse timestamp from Unix epoch seconds or ISO string
            DateTime timestamp = DateTime.UtcNow;
            if (root.TryGetProperty("timestamp", out var ts))
            {
                if (ts.ValueKind == JsonValueKind.Number && ts.TryGetInt64(out long epoch))
                    timestamp = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
                else if (ts.ValueKind == JsonValueKind.String && ts.GetString() is string tsStr)
                    // V-17: use InvariantCulture so locale differences don't break timestamp parsing
                    DateTime.TryParse(tsStr, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.RoundtripKind, out timestamp);
            }

            var severity = ParseEnum<LogSeverityManaged>(root, "severity");
            var action   = ParseEnum<LoadActionManaged>(root, "action");
            var risk     = ParseEnum<RiskLevelManaged>(root, "risk_level");
            var reasons  = ParseEnum<BlockReasonManaged>(root, "block_reasons");

            bool hmacPresent = root.TryGetProperty("hmac_sha256", out var hmac) &&
                               hmac.ValueKind == JsonValueKind.String &&
                               !string.IsNullOrEmpty(hmac.GetString());

            return new LogEventModel
            {
                Timestamp    = timestamp,
                Severity     = severity,
                SourceModule = GetString(root, "source_module"),
                HostName     = GetString(root, "host_name"),
                ProcessName  = GetString(root, "process_name"),
                ProcessId    = GetInt(root, "process_id"),
                DllPath      = GetString(root, "dll_path"),
                TrustScore   = GetDouble(root, "trust_score"),
                Action       = action,
                BlockReasons = reasons,
                RiskLevel    = risk,
                HmacPresent  = hmacPresent,
            };
        }
        catch (Exception ex)
        {
            // V-20: log parse failure for diagnosability
            System.Diagnostics.Debug.WriteLine($"[LogFileReader] Failed to parse log line: {ex.Message}");
            return null;
        }
    }

    private static T ParseEnum<T>(JsonElement root, string key) where T : struct, Enum
    {
        if (root.TryGetProperty(key, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out int v))
                return (T)(object)v;
            if (prop.ValueKind == JsonValueKind.String &&
                Enum.TryParse<T>(prop.GetString(), ignoreCase: true, out var e))
                return e;
        }
        return default;
    }

    private static string GetString(JsonElement root, string key) =>
        root.TryGetProperty(key, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? string.Empty
            : string.Empty;

    private static int GetInt(JsonElement root, string key) =>
        root.TryGetProperty(key, out var p) && p.TryGetInt32(out int v) ? v : 0;

    private static double GetDouble(JsonElement root, string key) =>
        root.TryGetProperty(key, out var p) && p.TryGetDouble(out double v) ? v : 0.0;
}
