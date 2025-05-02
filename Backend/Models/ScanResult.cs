using System;
using System.Collections.Generic;

namespace Page_Navigation_App.Backend.Models
{
    public class ScanResult
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; }
        public string HashType { get; set; } // MD5 or SHA256
        public bool IsInfected { get; set; }
        public bool IsSuccess { get; set; }
        public string ThreatName { get; set; }
        public string ThreatSignatureId { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public DateTime ScanTime { get; set; }
        public Dictionary<string, object> AdditionalData { get; set; } = new Dictionary<string, object>();
        public string VirusName { get; internal set; }
        public bool IsVirus { get; internal set; }
        
        public ScanResult()
        {
            IsInfected = false;
            IsSuccess = true;
            ThreatLevel = ThreatLevel.None;
            ScanTime = DateTime.Now;
            HashType = "MD5"; // Default hash type
        }

        public override string ToString()
        {
            return $"{FileName} - {(IsInfected ? $"INFECTED: {ThreatName} ({ThreatLevel})" : "Clean")}";
        }
    }
}