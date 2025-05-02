using System;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms; // For MessageBox
using Page_Navigation_App.Backend.Database;
using Page_Navigation_App.Backend.Models;
using Page_Navigation_App.Backend.Scanner;

namespace Page_Navigation_App.Backend.Protection
{
    public class RealTimeProtection
    {
        private readonly FileScanner _fileScanner;
        private readonly SignatureDatabase _signatureDatabase;
        private readonly List<FileSystemWatcher> _fileWatchers = new List<FileSystemWatcher>();
        private readonly List<ManagementEventWatcher> _deviceWatchers = new List<ManagementEventWatcher>();
        private readonly HashSet<string> _monitoredExtensions;
        private bool _isRunning = false;
        private readonly object _lock = new object();
        private readonly SemaphoreSlim _scanSemaphore;

        // Statistics tracking
        private int _totalScannedFiles = 0;
        private int _totalThreatsDetected = 0;
        private DateTime _startTime;

        // Configuration settings
        private int _maxConcurrentScans = 2;
        private bool _scanRemovableDrives = true;
        private bool _showNotifications = true;
        private HashSet<string> _knownDrives = new HashSet<string>();

        // Events
        public event EventHandler<ScanResult> ThreatDetected;
        public event EventHandler<string> RemovableDriveDetected;
        public event EventHandler<string> ActivityLogged;

        public RealTimeProtection(FileScanner fileScanner, SignatureDatabase signatureDatabase)
        {
            _fileScanner = fileScanner ?? throw new ArgumentNullException(nameof(fileScanner));
            _signatureDatabase = signatureDatabase ?? throw new ArgumentNullException(nameof(signatureDatabase));
            _scanSemaphore = new SemaphoreSlim(_maxConcurrentScans);

            // Monitor only these high-risk extensions
            _monitoredExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".hta", ".msi",
                ".scr", ".pif", ".com", ".jar", ".reg", ".vbe", ".wsf"
            };

            // Subscribe to scanner's threat detected event
            _fileScanner.ThreatDetected += (sender, result) =>
            {
                Interlocked.Increment(ref _totalThreatsDetected);
                ThreatDetected?.Invoke(this, result);
                LogActivity($"Threat detected: {result.ThreatName} in {result.FilePath}");
            };
        }

        public bool IsRunning => _isRunning;
        public int TotalScannedFiles => _totalScannedFiles;
        public int TotalThreatsDetected => _totalThreatsDetected;
        public TimeSpan RunningTime => _isRunning ? DateTime.Now - _startTime : TimeSpan.Zero;

        public void SetMaxConcurrentScans(int value)
        {
            if (value < 1 || value > 8)
                throw new ArgumentOutOfRangeException(nameof(value), "Value must be between 1 and 8");

            _maxConcurrentScans = value;
        }

        public void SetScanRemovableDrives(bool enable)
        {
            _scanRemovableDrives = enable;
        }

        public void SetShowNotifications(bool enable)
        {
            _showNotifications = enable;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_isRunning)
                    return;

                LogActivity("Starting real-time protection...");
                _isRunning = true;
                _startTime = DateTime.Now;
                _totalScannedFiles = 0;
                _totalThreatsDetected = 0;

                // Setup file system watchers for key directories
                SetupFileSystemWatchers();

                // Setup USB drive monitoring if enabled
                if (_scanRemovableDrives)
                {
                    SetupRemovableDriveMonitoring();
                }

                LogActivity("Real-time protection started successfully");
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning)
                    return;

                LogActivity("Stopping real-time protection...");

                // Clean up file system watchers
                foreach (var watcher in _fileWatchers)
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Created -= OnFileCreated;
                    watcher.Changed -= OnFileChanged;
                    watcher.Dispose();
                }
                _fileWatchers.Clear();

                // Clean up device watchers
                foreach (var watcher in _deviceWatchers)
                {
                    try
                    {
                        watcher.Stop();
                        watcher.EventArrived -= OnDeviceConnected;
                        watcher.Dispose();
                    }
                    catch (Exception ex)
                    {
                        LogActivity($"Error stopping device watcher: {ex.Message}");
                    }
                }
                _deviceWatchers.Clear();

                _isRunning = false;
                LogActivity("Real-time protection stopped");
            }
        }

        private void SetupFileSystemWatchers()
        {
            // List of important directories to monitor
            string[] keyDirectories = {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            };

            foreach (string directory in keyDirectories)
            {
                if (!Directory.Exists(directory))
                    continue;

                try
                {
                    var watcher = new FileSystemWatcher(directory)
                    {
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                        IncludeSubdirectories = true,
                        EnableRaisingEvents = true
                    };

                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileChanged;

                    _fileWatchers.Add(watcher);
                    LogActivity($"Monitoring directory: {directory}");
                }
                catch (Exception ex)
                {
                    LogActivity($"Error setting up watcher for {directory}: {ex.Message}");
                }
            }
        }

        private void SetupRemovableDriveMonitoring()
        {
            try
            {
                // Get current removable drives
                _knownDrives = new HashSet<string>(
                    DriveInfo.GetDrives()
                        .Where(d => d.IsReady && d.DriveType == DriveType.Removable)
                        .Select(d => d.Name)
                );

                // Set up WMI event watcher for USB insertion
                WqlEventQuery query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2");
                var insertWatcher = new ManagementEventWatcher(query);
                insertWatcher.EventArrived += OnDeviceConnected;
                insertWatcher.Start();
                _deviceWatchers.Add(insertWatcher);

                LogActivity("USB drive monitoring enabled");
            }
            catch (Exception ex)
            {
                LogActivity($"Error setting up USB monitoring: {ex.Message}");
            }
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            LogActivity($"[DEBUG] OnFileCreated event for: {e.FullPath}");
            if (!_isRunning || !IsTargetFile(e.FullPath))
                return;

            LogActivity($"New file detected: {e.FullPath}");
            QueueFileForScanning(e.FullPath);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            LogActivity($"[DEBUG] OnFileChanged event for: {e.FullPath}");
            if (!_isRunning || !IsTargetFile(e.FullPath))
                return;

            LogActivity($"Changed file detected: {e.FullPath}");
            QueueFileForScanning(e.FullPath);
        }

        private void OnDeviceConnected(object sender, EventArrivedEventArgs e)
        {
            if (!_isRunning || !_scanRemovableDrives)
                return;

            Task.Run(() => CheckForNewRemovableDrives());
        }

        private void CheckForNewRemovableDrives()
        {
            try
            {
                var currentDrives = DriveInfo.GetDrives()
                    .Where(d => d.IsReady && d.DriveType == DriveType.Removable)
                    .Select(d => d.Name)
                    .ToHashSet();

                var newDrives = currentDrives.Except(_knownDrives).ToList();

                foreach (var drive in newDrives)
                {
                    LogActivity($"New removable drive detected: {drive}");
                    RemovableDriveDetected?.Invoke(this, drive);

                    if (_showNotifications)
                    {
                        ShowNotification($"USB drive detected: {drive}", "Scanning will begin automatically.");
                    }

                    // Scan the drive in the background
                    Task.Run(async () =>
                    {
                        try
                        {
                            LogActivity($"Starting scan of removable drive: {drive}");
                            var scanSession = await _fileScanner.ScanDirectoryAsync(drive, true);
                            LogActivity($"Completed scan of removable drive: {drive}. Found {scanSession.InfectedFiles.Count} threats.");
                        }
                        catch (Exception ex)
                        {
                            LogActivity($"Error scanning drive {drive}: {ex.Message}");
                        }
                    });
                }

                // Update known drives
                _knownDrives = currentDrives;
            }
            catch (Exception ex)
            {
                LogActivity($"Error checking for new drives: {ex.Message}");
            }
        }

        private bool IsTargetFile(string path)
        {
            try
            {
                // Skip directories
                if (Directory.Exists(path))
                    return false;

                // Skip very large files
                var fileInfo = new FileInfo(path);
                if (fileInfo.Length > 50 * 1024 * 1024) // 50MB
                    return false;

                // Scan all files regardless of extension
                return true;
            }
            catch
            {
                return false;
            }
        }

        private async void QueueFileForScanning(string filePath)
        {
            LogActivity($"[DEBUG] QueueFileForScanning called for: {filePath}");
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return;

            await _scanSemaphore.WaitAsync();

            try
            {
                if (!_isRunning)
                    return;

                await Task.Delay(500);

                if (!File.Exists(filePath))
                    return;

                LogActivity($"Scanning file: {filePath}");

                // Heuristic scan first
                if (Page_Navigation_App.Backend.HeuristicScanner.IsSuspicious(filePath, out string reason))
                {
                    // Quarantine and log
                    string quarantinePath = QuarantineManager.QuarantineFile(filePath);
                    LogActivity($"Heuristic threat detected: {reason} in {quarantinePath}");
                    ThreatDetected?.Invoke(this, new ScanResult
                    {
                        FilePath = quarantinePath,
                        ThreatName = $"Heuristic: {reason}",
                        IsInfected = true
                    });
                    return; // Skip further scanning
                }

                // Scan the file using existing FileScanner
                var result = await _fileScanner.ScanFileAsync(filePath);

                Interlocked.Increment(ref _totalScannedFiles);

                if (result.IsInfected && _showNotifications)
                {
                    ShowNotification(
                        $"Threat Detected: {result.ThreatName}",
                        $"File: {Path.GetFileName(filePath)}\nLocation: {Path.GetDirectoryName(filePath)}"
                    );
                }
            }
            catch (Exception ex)
            {
                LogActivity($"Error scanning {filePath}: {ex.Message}");
            }
            finally
            {
                _scanSemaphore.Release();
            }
        }

        private void ShowNotification(string title, string message)
        {
            try
            {
                // Don't use MessageBox, just log the notification
                if (_showNotifications)
                {
                    // Just log to debug output instead of showing a message box
                    Debug.WriteLine($"[Notification] {title}: {message}");
                    
                    // The UI will be updated through the ThreatDetected event
                    // which the USBProtectionVM subscribes to
                }
            }
            catch
            {
                // Ignore notification errors
            }
        }

        private void LogActivity(string message)
        {
            Debug.WriteLine($"[RealTimeProtection] {message}");
            ActivityLogged?.Invoke(this, message);
        }
    }
}