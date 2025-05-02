using System;
using System.Collections.Generic;

public class LogEntry
{
    public string FileName { get; set; }
    public string FilePath { get; set; }
    public string ScanName { get; set; }
    public DateTime Date { get; set; }
    public List<string> Threats { get; set; } = new List<string>();
    public string FullText { get; set; }
}
