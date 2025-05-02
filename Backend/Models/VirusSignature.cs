using System;
using Page_Navigation_App.Backend.Models;

namespace Page_Navigation_App.Backend.Database
{
    public class VirusSignature
    {
        public string SignatureId { get; set; }
        public string ThreatName { get; set; }
        public string Hash { get; set; }
        public string HashType { get; set; } = "MD5";  // Default to MD5
        public ThreatLevel Severity { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public string FileType { get; internal set; }

        public override string ToString()
        {
            return $"{ThreatName} [{SignatureId}] - {Severity} ({HashType})";
        }
    }
}