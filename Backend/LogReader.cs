using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Linq;

public static class LogReader
{
    public static List<LogEntry> LoadLogs(string logsFolder)
    {
        var logs = new List<LogEntry>();
        if (!Directory.Exists(logsFolder))
            return logs;

        foreach (var file in Directory.GetFiles(logsFolder, "*.txt"))
        {
            try
            {
                var entry = ParseLogFile(file);
                if (entry != null)
                    logs.Add(entry);
            }
            catch { }
        }
        return logs;
    }

    public static IEnumerable<string> GetAllLogFiles(string logsFolder)
    {
        if (!Directory.Exists(logsFolder))
            return Enumerable.Empty<string>();
        return Directory.GetFiles(logsFolder, "*.txt");
    }

    private static LogEntry ParseLogFile(string filePath)
    {
        try
        {
            var lines = File.ReadAllLines(filePath);
            if (lines.Length < 4)
                return null;
            var entry = new LogEntry();
            entry.FileName = Path.GetFileName(filePath);
            entry.FilePath = filePath;
            entry.ScanName = lines[0].Trim();
            // Date is on line 2 or 3 depending on blank lines
            string dateLine = lines.Length > 2 ? lines[2].Trim() : string.Empty;
            if (!string.IsNullOrWhiteSpace(dateLine) && DateTime.TryParse(dateLine, out DateTime dt))
                entry.Date = dt;
            else
                entry.Date = File.GetCreationTime(filePath);

            entry.FullText = string.Join("\n", lines);
            entry.Threats = new List<string>();
            // Find 'Threats found:' and read subsequent lines
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Trim().StartsWith("Threats found:"))
                {
                    for (int j = i + 1; j < lines.Length; j++)
                    {
                        if (!string.IsNullOrWhiteSpace(lines[j]) && lines[j].Trim() != "None")
                            entry.Threats.Add(lines[j].Trim());
                    }
                    break;
                }
            }
            return entry;
        }
        catch
        {
            // If any error occurs, skip this log file
            return null;
        }
    }
}
