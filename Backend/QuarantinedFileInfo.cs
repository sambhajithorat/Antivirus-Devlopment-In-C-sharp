using System;

public class QuarantinedFileInfo
{
    public string FileName { get; set; }
    public string FullPath { get; set; }
    public long Size { get; set; }
    public DateTime Date { get; set; }
    public string OriginalPath { get; set; } // For restoration
}
