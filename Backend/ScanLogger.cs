using System;
using System.Collections.Generic;
using System.IO;

namespace Page_Navigation_App.Backend
{
    public static class ScanLogger
    {
        private static readonly string logsFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "AntivirusLogs");

        static ScanLogger()
        {
            if (!Directory.Exists(logsFolder))
                Directory.CreateDirectory(logsFolder);
        }

        /// <summary>
        /// Creates a log file for a scan with the required format.
        /// </summary>
        /// <param name="scanName">Name of the scan (e.g., Smart Sweep, System Sweep)</param>
        /// <param name="threatNames">List of threat names found</param>
        public static string LogScan(string scanName, List<string> threatNames)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logFileName = $"{scanName.Replace(" ", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            string logFilePath = Path.Combine(logsFolder, logFileName);

            using (var writer = new StreamWriter(logFilePath))
            {
                writer.WriteLine(scanName); // Line 1: Scan name
                writer.WriteLine(); // Line 2: Blank
                writer.WriteLine(timestamp); // Line 3: Date/time
                writer.WriteLine("Threat Quarantined"); // Line 4: Quarantine info
                // Line 5: File name(s) detected as threat, or 'None'
                if (threatNames != null && threatNames.Count > 0)
                    writer.WriteLine(string.Join(", ", threatNames));
                else
                    writer.WriteLine("None");
                writer.WriteLine("Threats found:");
                if (threatNames != null && threatNames.Count > 0)
                {
                    foreach (var threat in threatNames)
                        writer.WriteLine(threat);
                }
                else
                {
                    writer.WriteLine("None");
                }
            }
            return logFilePath;
        }

        public static string GetLogsFolder()
        {
            return logsFolder;
        }

        public static List<string> GetAllLogFiles()
        {
            if (!Directory.Exists(logsFolder))
                return new List<string>();
            return new List<string>(Directory.GetFiles(logsFolder, "*.txt"));
        }

    }
}