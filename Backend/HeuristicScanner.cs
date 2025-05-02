using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Page_Navigation_App.Backend
{
    public static class HeuristicScanner
    {
        // Helper to get Downloads folder path for all .NET versions
        public static string GetDownloadsFolder()
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloads = Path.Combine(home, "Downloads");
            return downloads;
        }
        // Main entry point: returns true if suspicious, and reason
        public static bool IsSuspicious(string filePath, out string reason)
        {
            reason = null;
            if (!File.Exists(filePath)) return false;

            // 1. Double extension
            if (HasDoubleExtension(filePath))
            {
                reason = "Double extension (e.g. .pdf.exe)";
                return true;
            }

            // 2. High entropy
            if (IsHighEntropy(filePath))
            {
                reason = "High entropy (packed/encrypted file)";
                return true;
            }

            // 3. Suspicious file type in user folders
            if (IsSuspiciousFileTypeInUserFolder(filePath))
            {
                reason = "Suspicious file type in user folder (exe/script)";
                return true;
            }

            // 4. Macro detection for Office files
            if (HasOfficeMacros(filePath))
            {
                reason = "Office document with macros";
                return true;
            }

            // 5. Packed executable
            if (IsPackedExecutable(filePath))
            {
                reason = "Packed or obfuscated executable";
                return true;
            }

            // 6. Suspicious file name
            if (HasSuspiciousName(filePath))
            {
                reason = "Suspicious file name pattern";
                return true;
            }

            // 7. Script/batch file in user folder
            if (IsScriptOrBatch(filePath))
            {
                reason = "Script or batch file in user folder";
                return true;
            }

            return false;
        }

        // --- Heuristic implementations ---
        static bool HasDoubleExtension(string filePath)
        {
            var name = Path.GetFileName(filePath);
            var parts = name.Split('.');
            if (parts.Length < 3) return false;
            var ext = Path.GetExtension(filePath).ToLower();
            string[] risky = { ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1" };
            return risky.Contains(ext);
        }

        static bool IsHighEntropy(string filePath, int sampleSize = 4096)
        {
            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                if (data.Length > sampleSize)
                    data = data.Take(sampleSize).ToArray();
                double entropy = 0;
                int[] counts = new int[256];
                foreach (byte b in data) counts[b]++;
                foreach (int c in counts)
                {
                    if (c == 0) continue;
                    double p = c / (double)data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
                return entropy > 7.5; // High entropy threshold
            }
            catch { return false; }
        }

        static bool IsSuspiciousFileTypeInUserFolder(string filePath)
        {
            string[] userFolders = {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                GetDownloadsFolder()
            };
            string ext = Path.GetExtension(filePath).ToLower();
            string[] risky = { ".exe", ".dll", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".scr" };
            return userFolders.Any(f => filePath.StartsWith(f, StringComparison.OrdinalIgnoreCase)) && risky.Contains(ext);
        }

        static bool HasOfficeMacros(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLower();
            if (!(ext == ".docm" || ext == ".xlsm" || ext == ".pptm")) return false;
            // Quick check: look for vbaProject.bin in file (macro container)
            try
            {
                using (var fs = File.OpenRead(filePath))
                using (var reader = new BinaryReader(fs))
                {
                    byte[] buffer = new byte[8192];
                    int read = reader.Read(buffer, 0, buffer.Length);
                    string content = Encoding.UTF8.GetString(buffer, 0, read);
                    return content.Contains("vbaProject.bin");
                }
            }
            catch { return false; }
        }

        static bool IsPackedExecutable(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLower();
            if (ext != ".exe" && ext != ".dll") return false;
            try
            {
                using (var fs = File.OpenRead(filePath))
                using (var reader = new BinaryReader(fs))
                {
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peHeader = reader.ReadInt32();
                    fs.Seek(peHeader + 0x6, SeekOrigin.Begin);
                    ushort numSections = reader.ReadUInt16();
                    fs.Seek(peHeader + 0xF8, SeekOrigin.Begin);
                    for (int i = 0; i < numSections; i++)
                    {
                        byte[] nameBytes = reader.ReadBytes(8);
                        string sectionName = Encoding.UTF8.GetString(nameBytes).Trim('\0');
                        if (sectionName.ToLower().Contains("upx"))
                            return true;
                        fs.Seek(32, SeekOrigin.Current);
                    }
                }
            }
            catch { }
            return false;
        }

        static bool HasSuspiciousName(string filePath)
        {
            string name = Path.GetFileName(filePath).ToLower();
            if (name.Contains("password") || name.Contains("invoice") || name.Contains("bank"))
            {
                string ext = Path.GetExtension(filePath).ToLower();
                string[] risky = { ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd" };
                if (risky.Contains(ext)) return true;
            }
            return false;
        }

        static bool IsScriptOrBatch(string filePath)
        {
            string ext = Path.GetExtension(filePath).ToLower();
            string[] risky = { ".js", ".vbs", ".bat", ".cmd", ".ps1" };
            string[] userFolders = {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                GetDownloadsFolder()
            };
            return userFolders.Any(f => filePath.StartsWith(f, StringComparison.OrdinalIgnoreCase)) && risky.Contains(ext);
        }
    }
}
