using System.Data.SQLite;
using System.Collections.Concurrent;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Page_Navigation_App.Backend.Models;
using System.Linq;
using System.Diagnostics;

namespace Page_Navigation_App.Backend.Database
{
    public class SignatureDatabase
    {
        private List<VirusSignature> _signatures;
        public DateTime LastUpdateTime { get; private set; }
        private string _databaseFilePath = @"C:\Users\slico\source\repos\Page-Navigation-using-MVVM\Source Code\Page Navigation App\Page Navigation App\Page Navigation App\Data\virus_signatures.db.db";

        // Dictionary to hold virus signatures: Key = file hash, Value = threat name
        private readonly Dictionary<string, string> _knownThreats;
        
        // List of common virus file names
        private readonly HashSet<string> _suspiciousFileNames;

        public int SignaturesCount
        {
            get { return _signatures?.Count ?? 0; }
        }

        public SignatureDatabase()
        {
            _signatures = new List<VirusSignature>();
            _knownThreats = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _suspiciousFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            if (!File.Exists(_databaseFilePath))
            {
                
              //  $"Database file not found at: {_databaseFilePath}";
                InitializeDefaultSignatures();
            }
            LastUpdateTime = DateTime.Now;
        }

        public async Task InitializeAsync()
        {
            if (File.Exists(_databaseFilePath))
            {
                try
                {
                    await RefreshSignaturesFromDatabase();
                  //  Console.WriteLine($"Loaded {_signatures.Count} signatures from database");
                }
                catch (Exception)
                {
                 //   Console.WriteLine($"Error loading from database: {ex.Message}");
                    InitializeDefaultSignatures();
                    throw; // Let the UI layer handle user notification
                }
            }
            else
            {
                InitializeDefaultSignatures();
            }
        }

        private void InitializeDefaultSignatures()
        {
            _signatures.Add(new VirusSignature
            {
                SignatureId = "VX001",
                ThreatName = "Test.Malware.Generic",
                Hash = "E1112134F65BB8304AEC5B80BEEE3CD4",
                Severity = ThreatLevel.Medium,
                Description = "Test malware signature"
            });

            _signatures.Add(new VirusSignature
            {
                SignatureId = "VX002",
                ThreatName = "Trojan.Ransomware.Test",
                Hash = "7890123456789012345678901234567890123456",
                Severity = ThreatLevel.Critical,
                Description = "Test ransomware signature",
                HashType = "SHA256"
            });

            _signatures.Add(new VirusSignature
            {
                SignatureId = "VX003",
                ThreatName = "Adware.Test.Generic",
                Hash = "ABCDEF0123456789",
                Severity = ThreatLevel.Low,
                Description = "Test adware signature"
            });

            _signatures.Add(new VirusSignature
            {
                SignatureId = "VX004",
                ThreatName = "Rootkit.Test.A",
                Hash = "00112233445566778899AABBCCDDEEFF",
                Severity = ThreatLevel.High,
                Description = "Test rootkit signature"
            });

            _signatures.Add(new VirusSignature
            {
                SignatureId = "VX005",
                ThreatName = "EICAR-Test-File",
                Hash = "44D88612FEA8A8F36DE82E1278ABB02F",
                Severity = ThreatLevel.Medium,
                Description = "EICAR Anti-Virus Test File"
            });

           // Console.WriteLine($"Initialized {_signatures.Count} test signatures");
        }

        public async Task RefreshSignaturesFromDatabase()
        {
            var tempSignatures = new List<VirusSignature>();
            try
            {
                using (var connection = new SQLiteConnection($"Data Source={_databaseFilePath};Version=3;"))
                {
                    await connection.OpenAsync();

                    string query = "SELECT Md5, Sha256, FileType, Signature FROM VirusSignatures";
                    using (var command = new SQLiteCommand(query, connection))
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            string md5 = reader["Md5"].ToString();
                            string sha256 = reader["Sha256"].ToString();
                            string fileType = reader["FileType"].ToString();
                                                        string signature = reader["Signature"].ToString();

                            tempSignatures.Add(new VirusSignature
                            {
                                Hash = sha256,
                                ThreatName = signature,
                                FileType = fileType
                            });
                        }
                    }
                }

                _signatures = tempSignatures;
                LastUpdateTime = DateTime.Now;
               // Console.WriteLine($"Successfully loaded {_signatures.Count} signatures from database");
            }
            catch (Exception)
            {
              //  Console.WriteLine($"Error in RefreshSignaturesFromDatabase: {ex.Message}");
                throw; // Let the UI layer handle user notification
            }
        }

        private ThreatLevel GetThreatLevelFromString(string level)
        {
            switch (level?.ToLower() ?? "medium")
            {
                case "critical":
                    return ThreatLevel.Critical;
                case "high":
                    return ThreatLevel.High;
                case "medium":
                    return ThreatLevel.Medium;
                case "low":
                    return ThreatLevel.Low;
                default:
                    return ThreatLevel.Medium;
            }
        }

        public bool IsFileInfected(string fileHash, out VirusSignature matchedSignature)
        {
            if (string.IsNullOrEmpty(fileHash))
            {
                matchedSignature = null;
                return false;
            }

            matchedSignature = null;
            
            // Normalize the hash to lowercase for consistent comparison
            string normalizedHash = fileHash.ToLowerInvariant();
            
            // First check in _signatures collection
            foreach (var signature in _signatures)
            {
                if (signature.Hash.Equals(normalizedHash, StringComparison.OrdinalIgnoreCase))
                {
                    matchedSignature = signature;
                    return true;
                }
            }
            
            // Then check in _knownThreats dictionary
            if (_knownThreats.TryGetValue(normalizedHash, out string threatName))
            {
                // Create a new signature object for the threat found in _knownThreats
                matchedSignature = new VirusSignature
                {
                    SignatureId = "KT" + normalizedHash.Substring(0, 6),
                    ThreatName = threatName,
                    Hash = normalizedHash,
                    Severity = ThreatLevel.Medium, // Default severity
                    Description = "Threat detected from known threats database"
                };
                return true;
            }
            
            // No match found in either collection
            return false;
        }

        public string CalculateFileSHA256(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            try
            {
                using (var sha256 = SHA256.Create())
                {
                    using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        var hash = sha256.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                    }
                }
            }
            catch (IOException)
            {
              //  Console.WriteLine($"IO Exception when calculating SHA256 for {filePath}: {ex.Message}");
                throw;
            }
            catch (UnauthorizedAccessException)
            {
               // Console.WriteLine($"Access denied when calculating SHA256 for {filePath}: {ex.Message}");
                throw;
            }
        }

        public void AddSignature(VirusSignature signature)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            _signatures.Add(signature);
        }

        public void RemoveSignature(string signatureId)
        {
            _signatures.RemoveAll(s => s.SignatureId == signatureId);
        }

        public List<VirusSignature> GetAllSignatures()
        {
            return new List<VirusSignature>(_signatures);
        }

        private void InitializeDatabase()
        {
            // In a real antivirus, this would load from a file or download from a server
            // Here we're just adding some sample signatures
            
            // Sample virus signatures (MD5 hashes)
            _knownThreats.Add("e44fcd4ca3d3e30e37e7575d231d508c", "Trojan.Win32.Generic");
            _knownThreats.Add("84c82835a5d21bbcf75a61706d8ab549", "Exploit.PDF-JS.Gen");
            _knownThreats.Add("5f4dcc3b5aa765d61d8327deb882cf99", "Backdoor.Win32.BlackEnergy");
            _knownThreats.Add("098f6bcd4621d373cade4e832627b4f6", "Worm.Win32.NetSky");
            _knownThreats.Add("81dc9bdb52d04dc20036dbd8313ed055", "Ransomware.Crypto");
            _knownThreats.Add("d8578edf8458ce06fbc5bb76a58c5ca4", "Virus.Win32.Sality");
            _knownThreats.Add("1234567890abcdef1234567890abcdef", "Trojan.Downloader");
            _knownThreats.Add("abcdef1234567890abcdef1234567890", "Backdoor.Generic");
            _knownThreats.Add("e10adc3949ba59abbe56e057f20f883e", "Malware.Suspicious");
            
            // Common suspicious file names
            _suspiciousFileNames.Add("virus.exe");
            _suspiciousFileNames.Add("trojan.exe");
            _suspiciousFileNames.Add("hack.exe");
            _suspiciousFileNames.Add("crack.exe");
            _suspiciousFileNames.Add("keygen.exe");
            _suspiciousFileNames.Add("backdoor.exe");
            _suspiciousFileNames.Add("rootkit.exe");
            _suspiciousFileNames.Add("ransomware.exe");
            _suspiciousFileNames.Add("spyware.exe");
            _suspiciousFileNames.Add("worm.exe");
            _suspiciousFileNames.Add("keylogger.exe");
            _suspiciousFileNames.Add("autorun.inf");
        }
        
        /// <summary>
        /// Check if a file hash matches a known threat signature
        /// </summary>
        public bool IsKnownThreat(string fileHash)
        {
            if (string.IsNullOrEmpty(fileHash))
                return false;
                
            return _knownThreats.ContainsKey(fileHash);
        }
        
        /// <summary>
        /// Get the name of the threat associated with a file hash
        /// </summary>
        public string GetThreatName(string fileHash)
        {
            if (string.IsNullOrEmpty(fileHash))
                return null;
                
            if (_knownThreats.TryGetValue(fileHash, out string threatName))
                return threatName;
                
            return null;
        }
        
        /// <summary>
        /// Check if a filename is suspicious
        /// </summary>
        public bool IsSuspiciousFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return false;
                
            // Get just the filename without path
            string name = Path.GetFileName(fileName);
            
            return _suspiciousFileNames.Contains(name);
        }
        
        /// <summary>
        /// Asynchronously update the database (simulated)
        /// </summary>
        public async Task<bool> UpdateDatabaseAsync()
        {
            // In a real application, this would download updated signatures
            // from a server. Here we'll just simulate a delay
            
            try
            {
                Debug.WriteLine("Updating virus signature database...");
                await Task.Delay(2000); // Simulate download time
                
                // Add a few more signatures to simulate the update
                _knownThreats["c8e7f6a544a0a5f65b8dd25558cee7d3"] = "Trojan.Win32.Updated";
                _knownThreats["452ce5c9f2ee9037a2cf764e5dc123f9"] = "Virus.Win32.NewVariant";
                
                Debug.WriteLine("Virus signature database updated successfully");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error updating virus database: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// Get the number of signatures in the database
        /// </summary>
        public int SignatureCount => _knownThreats.Count;
    }
}