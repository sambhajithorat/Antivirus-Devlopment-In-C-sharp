using System;
using System.Collections.Generic;

namespace Page_Navigation_App.Backend.Models
{
    public class ScanSession
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public string Path { get; set; }
        public bool IsCompleted { get; set; }
        public bool IsCancelled { get; set; }
        public string ErrorMessage { get; set; }
        public List<ScanResult> InfectedFiles { get; set; }
        public List<string> InaccessibleFiles { get; set; }
        public List<string> InaccessibleDirectories { get; set; }
        public List<string> ErrorFiles { get; set; }
        public int TotalScannedFiles { get; set; }

        public ScanSession()
        {
            StartTime = DateTime.Now;
            IsCompleted = false;
            IsCancelled = false;
            InfectedFiles = new List<ScanResult>();
            InaccessibleFiles = new List<string>();
            InaccessibleDirectories = new List<string>();
            ErrorFiles = new List<string>();
            TotalScannedFiles = 0;
        }

        public TimeSpan Duration
        {
            get { return EndTime - StartTime; }
        }

        public override string ToString()
        {
            return $"Scan of {Path}: {TotalScannedFiles} files scanned, {InfectedFiles.Count} infected, {Duration.TotalSeconds:F1} seconds";
        }
    }
}