using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms; // Added for MessageBox
using Page_Navigation_App.Backend.Database;
using Page_Navigation_App.Backend.Models;

namespace Page_Navigation_App.Backend.Scanner
{
    public class FileScanner
    {
        private readonly SignatureDatabase _signatureDatabase;
        private readonly List<ScanResult> _detectedThreats;
        private readonly object _detectedThreatsLock = new object(); // Dedicated lock object
        private CancellationTokenSource _cancellationTokenSource;
        
        // Cache of recently scanned file hashes to avoid redundant calculations
        private readonly Dictionary<string, string> _hashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _hashCacheLock = new object();
        private const int MaxHashCacheSize = 1000;

        private bool _isScanning;
        private static readonly HashSet<string> _commonExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".msi", ".scr",
            ".com", ".pif", ".jar", ".wsf", ".jse", ".vbe", ".wsh", ".hta"
        };

        // Events
        public event EventHandler<ScanResult> FileScanned;
        public event EventHandler<ScanResult> ThreatDetected;
        public event EventHandler<int> ScanProgressUpdated;
        public event EventHandler<List<ScanResult>> ScanCompleted;

        public FileScanner(SignatureDatabase signatureDatabase)
        {
            _signatureDatabase = signatureDatabase ?? throw new ArgumentNullException(nameof(signatureDatabase));
            _detectedThreats = new List<ScanResult>();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public bool IsScanning => _isScanning;

        public void CancelScan()
        {
            _cancellationTokenSource?.Cancel();
            // Create a new token source for the next scan
            _cancellationTokenSource = new CancellationTokenSource();
        }

        public async Task<ScanResult> ScanFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"File not found: {filePath}");
                return new ScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    IsInfected = false,
                    IsSuccess = false,
                    ScanTime = DateTime.Now,
                    ThreatName = "File not found"
                };
            }

            try
            {
                // Check for cancellation
                _cancellationTokenSource?.Token.ThrowIfCancellationRequested();

                // Skip very large files (over 100MB) for performance
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    return new ScanResult
                    {
                        FilePath = filePath,
                        FileName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        ScanTime = DateTime.Now,
                        IsSuccess = true,
                        IsInfected = false,
                        ThreatName = "Skipped (large file)"
                    };
                }

                var scanResult = new ScanResult
                {
                    FilePath = filePath,
                    FileName = fileInfo.Name,
                    FileSize = fileInfo.Length,
                    ScanTime = DateTime.Now,
                    IsSuccess = true
                };

                // Fast path - check the hash cache first before computing hash
                string sha256Hash = null;
                bool hashCacheHit = false;
                
                lock (_hashCacheLock)
                {
                    if (_hashCache.TryGetValue(filePath, out sha256Hash))
                    {
                        hashCacheHit = true;
                    }
                }

                if (!hashCacheHit)
                {
                    // Check for cancellation before hash calculation 
                    _cancellationTokenSource?.Token.ThrowIfCancellationRequested();

                    // Calculate hash in a separate task to keep UI responsive
                    sha256Hash = await Task.Run(() => CalculateFileSHA256(filePath));
                    
                    // Add to cache
                    lock (_hashCacheLock)
                    {
                        // Remove oldest entry if cache is full
                        if (_hashCache.Count >= MaxHashCacheSize)
                        {
                            // Simple strategy: just clear half the cache
                            int toRemove = _hashCache.Count / 2;
                            int removed = 0;
                            var keysToRemove = new List<string>();
                            
                            foreach (var key in _hashCache.Keys)
                            {
                                keysToRemove.Add(key);
                                removed++;
                                if (removed >= toRemove) break;
                            }
                            
                            foreach (var key in keysToRemove)
                            {
                                _hashCache.Remove(key);
                            }
                        }
                        
                        _hashCache[filePath] = sha256Hash;
                    }
                }

                // Store SHA256 hash in the result
                scanResult.FileHash = sha256Hash;
                scanResult.AdditionalData = null;

                // Trigger the FileScanned event to show scanning progress
                FileScanned?.Invoke(this, scanResult);

                // Check if file matches any virus signature - fix the out parameter issue
                VirusSignature signature = null;
                bool isInfected = _signatureDatabase.IsFileInfected(sha256Hash, out signature);
                
                if (isInfected && signature != null)
                {
                    scanResult.IsInfected = true;
                    scanResult.ThreatName = signature.ThreatName;
                    scanResult.ThreatLevel = signature.Severity;
                    scanResult.ThreatSignatureId = signature.SignatureId;
                    scanResult.HashType = "SHA256";
                    Console.WriteLine($"THREAT DETECTED: {filePath} - {signature.ThreatName}");
                    ThreatDetected?.Invoke(this, scanResult);

                    // Add to detected threats list
                    lock (_detectedThreatsLock)
                    {
                        _detectedThreats.Add(scanResult);
                    }
                }
                else
                {
                    Console.WriteLine($"No threat detected in: {filePath}");
                }

                return scanResult;
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine($"Scanning of {filePath} was cancelled.");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning file {filePath}: {ex.Message}");
                return new ScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    IsInfected = false,
                    IsSuccess = false,
                    ScanTime = DateTime.Now,
                    ThreatName = $"Error: {ex.Message}"
                };
            }
        }

        // Optimized SHA256 calculation with better error handling and resource management
        private string CalculateFileSHA256(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            try
            {
                // Use a smaller buffer for faster processing and less memory usage
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    const int bufferSize = 1024 * 1024; // 1MB buffer
                    byte[] buffer = new byte[bufferSize];
                    int bytesRead;
                    
                    using (var stream = new FileStream(
                        filePath, 
                        FileMode.Open, 
                        FileAccess.Read, 
                        FileShare.ReadWrite | FileShare.Delete,
                        bufferSize))
                    {
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                            
                            // Occasionally check for cancellation
                            _cancellationTokenSource?.Token.ThrowIfCancellationRequested();
                        }
                        
                        sha256.TransformFinalBlock(buffer, 0, 0);
                        return BitConverter.ToString(sha256.Hash).Replace("-", "").ToUpperInvariant();
                    }
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine($"IO Exception when calculating SHA256 for {filePath}: {ex.Message}");
                throw;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Access denied when calculating SHA256 for {filePath}: {ex.Message}");
                throw;
            }
        }

        public async Task<ScanSession> ScanDirectoryAsync(string directoryPath, bool includeSubdirectories, CancellationToken externalToken = default)
        {
            // Create a new linked token source that respects both our internal source and the external one
            using (var linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
                _cancellationTokenSource?.Token ?? CancellationToken.None,
                externalToken))
            {
                CancellationToken token = linkedTokenSource.Token;
                var session = new ScanSession
                {
                    StartTime = DateTime.Now,
                    Path = directoryPath
                };

                try
                {
                    if (!Directory.Exists(directoryPath))
                    {
                        Console.WriteLine($"Directory not found: {directoryPath}");
                        session.ErrorMessage = "Directory not found";
                        session.EndTime = DateTime.Now;
                        return session;
                    }

                    Console.WriteLine($"Starting scan on directory: {directoryPath}");

                    int totalFiles = await CountFilesInDirectoryAsync(directoryPath, includeSubdirectories);

                    // Create a progress tracker object instead of using ref
                    var progress = new ScanProgress { TotalFiles = totalFiles };

                    await ScanDirectoryRecursiveAsync(directoryPath, includeSubdirectories, session, progress, token);

                    session.EndTime = DateTime.Now;
                    session.IsCompleted = true;

                    // Notify listeners that scan is completed
                    ScanCompleted?.Invoke(this, GetDetectedThreats());

                    return session;
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("Scan was cancelled.");
                    session.EndTime = DateTime.Now;
                    session.IsCancelled = true;
                    return session;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error scanning directory: {ex.Message}");
                    session.EndTime = DateTime.Now;
                    session.ErrorMessage = ex.Message;
                    return session;
                }
            }
        }

        public async Task<ScanSession> ScanDriveAsync(string drivePath, bool scanAllFiles = false, CancellationToken cancellationToken = default)
        {
            if (_isScanning)
                throw new InvalidOperationException("A scan is already in progress");

            _isScanning = true;
            // Use the provided cancellation token or create a new one if not provided
            if (cancellationToken == default)
            {
                _cancellationTokenSource = new CancellationTokenSource();
            }
            else
            {
                // Use the provided token
                _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            }
            var scanSession = new ScanSession
            {
                StartTime = DateTime.Now,
                Path = drivePath,
                TotalScannedFiles = 0
            };

            try
            {
                var fileCount = CountFilesInDirectory(drivePath, scanAllFiles);
                int scannedCount = 0;

                // First, find all files to scan
                var filesToScan = await Task.Run(() => GetFilesToScan(drivePath, scanAllFiles));
                
                // Then scan each file
                foreach (var file in filesToScan)
                {
                    if (_cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        scanSession.IsCancelled = true;
                        break;
                    }

                    try
                    {
                        var scanResult = await ScanFileAsync(file);
                        scannedCount++;
                        
                        // Update progress
                        int progressPercentage = fileCount > 0 ? (scannedCount * 100) / fileCount : 100;
                        ScanProgressUpdated?.Invoke(this, progressPercentage);
                        
                        FileScanned?.Invoke(this, scanResult);
                        
                        if (scanResult.IsInfected)
                        {
                            scanSession.InfectedFiles.Add(scanResult);
                            ThreatDetected?.Invoke(this, scanResult);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error scanning file {file}: {ex.Message}");
                        scanSession.ErrorFiles.Add(file);
                    }
                }

                scanSession.EndTime = DateTime.Now;
                scanSession.TotalScannedFiles = scannedCount;
                scanSession.IsCompleted = true;
                
                return scanSession;
            }
            catch (Exception ex)
            {
                scanSession.ErrorMessage = ex.Message;
                return scanSession;
            }
            finally
            {
                _isScanning = false;
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
        }

        // Create a class to track progress
        private class ScanProgress
        {
            public int FilesScanned { get; set; }
            public int TotalFiles { get; set; }
        }

        private async Task ScanDirectoryRecursiveAsync(
            string directoryPath,
            bool includeSubdirectories,
            ScanSession session,
            ScanProgress progress,
            CancellationToken token)
        {
            try
            {
                // Scan files in the current directory
                string[] files = Directory.GetFiles(directoryPath);
                int updateInterval = Math.Max(1, files.Length / 20); // Update progress after 5% of files
                int filesSinceLastUpdate = 0;
                
                // Process files with limited concurrency to maintain responsiveness
                int maxConcurrency = Math.Min(Environment.ProcessorCount, 8); // Limit concurrency
                var scanTasks = new List<Task>();
                var semaphore = new SemaphoreSlim(maxConcurrency);
                
                foreach (var file in files)
                {
                    if (token.IsCancellationRequested)
                        break;
                    
                    // Wait for a slot in the semaphore before starting a new task
                    await semaphore.WaitAsync(token);
                    
                    var scanTask = Task.Run(async () =>
                    {
                        try
                        {
                            token.ThrowIfCancellationRequested();

                            try
                            {
                                ScanResult result = await ScanFileAsync(file);
                                progress.FilesScanned++;
                                filesSinceLastUpdate++;
                                // Throttle updates to avoid overwhelming the UI
                                if (filesSinceLastUpdate >= updateInterval)
                                {
                                    filesSinceLastUpdate = 0;
                                    if (progress.TotalFiles > 0)
                                    {
                                        int progressPercentage = (progress.TotalFiles > 0)
    ? (int)((double)progress.FilesScanned / progress.TotalFiles * 100)
    : 0;
                                        ScanProgressUpdated?.Invoke(this, progressPercentage);
                                    }
                                    
                                    // Allow UI thread to process
                                    await Task.Delay(1, token);
                                }

                                if (result.IsInfected)
                                {
                                    lock (session)
                                    {
                                        session.InfectedFiles.Add(result);
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException)
                            {
                                Console.WriteLine($"Access denied to file: {file}");
                                lock (session)
                                {
                                    session.InaccessibleFiles.Add(file);
                                }
                            }
                            catch (Exception ex) when (!(ex is OperationCanceledException))
                            {
                                Console.WriteLine($"Error scanning file {file}: {ex.Message}");
                                lock (session)
                                {
                                    session.ErrorFiles.Add(file);
                                }
                            }
                        }
                        finally
                        {
                            // Always release the semaphore slot when done
                            semaphore.Release();
                        }
                    }, token);
                    
                    scanTasks.Add(scanTask);
                }
                
                // Wait for all scan tasks to complete
                await Task.WhenAll(scanTasks);

                // Recursively scan subdirectories if requested
                if (includeSubdirectories)
                {
                    string[] subdirectories;
                    try
                    {
                        subdirectories = Directory.GetDirectories(directoryPath);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine($"Access denied to directory: {directoryPath}");
                        session.InaccessibleDirectories.Add(directoryPath);
                        return;
                    }

                    foreach (string subdirectory in subdirectories)
                    {
                        token.ThrowIfCancellationRequested();
                        await ScanDirectoryRecursiveAsync(subdirectory, true, session, progress, token);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw; // Re-throw for handling in the caller
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing directory {directoryPath}: {ex.Message}");
                session.ErrorMessage = ex.Message;
                session.InaccessibleDirectories.Add(directoryPath);
            }
        }

        private async Task<int> CountFilesInDirectoryAsync(string directoryPath, bool includeSubdirectories)
        {
            return await Task.Run(() =>
            {
                int count = 0;
                try
                {
                    count += Directory.GetFiles(directoryPath).Length;
                    if (includeSubdirectories)
                    {
                        foreach (string subdirectory in Directory.GetDirectories(directoryPath))
                        {
                            try
                            {
                                count += CountFilesInDirectoryAsync(subdirectory, true).GetAwaiter().GetResult();
                            }
                            catch (UnauthorizedAccessException)
                            {
                                // Skip directories we can't access
                                Console.WriteLine($"Access denied while counting files in: {subdirectory}");
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"Access denied while counting files in: {directoryPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error counting files in {directoryPath}: {ex.Message}");
                }
                return count;
            });
        }

        public List<ScanResult> GetDetectedThreats()
        {
            lock (_detectedThreatsLock)
            {
                return new List<ScanResult>(_detectedThreats); // Return a copy to ensure thread safety
            }
        }

        public void ClearDetectedThreats()
        {
            lock (_detectedThreatsLock)
            {
                _detectedThreats.Clear();
            }
        }

        private List<string> GetFilesToScan(string path, bool scanAllFiles)
        {
            var result = new List<string>();
            
            try
            {
                foreach (var file in Directory.GetFiles(path))
                {
                    if (_cancellationTokenSource?.Token.IsCancellationRequested == true)
                        break;

                    string extension = Path.GetExtension(file).ToLowerInvariant();
                    
                    // If scanAllFiles is true, or the file has an executable extension, add it
                    if (scanAllFiles || _commonExecutableExtensions.Contains(extension))
                    {
                        result.Add(file);
                    }
                }
                
                // Recursively scan subdirectories
                foreach (var dir in Directory.GetDirectories(path))
                {
                    if (_cancellationTokenSource?.Token.IsCancellationRequested == true)
                        break;
                        
                    try
                    {
                        result.AddRange(GetFilesToScan(dir, scanAllFiles));
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Skip directories we can't access
                        Debug.WriteLine($"Access denied to directory: {dir}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error scanning directory {path}: {ex.Message}");
            }
            
            return result;
        }

        private int CountFilesInDirectory(string path, bool scanAllFiles)
        {
            int count = 0;
            
            try
            {
                foreach (var file in Directory.GetFiles(path))
                {
                    string extension = Path.GetExtension(file).ToLowerInvariant();
                    if (scanAllFiles || _commonExecutableExtensions.Contains(extension))
                    {
                        count++;
                    }
                }
                
                foreach (var dir in Directory.GetDirectories(path))
                {
                    try
                    {
                        count += CountFilesInDirectory(dir, scanAllFiles);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Skip directories we can't access
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error counting files in {path}: {ex.Message}");
            }
            
            return count;
        }
    }
}