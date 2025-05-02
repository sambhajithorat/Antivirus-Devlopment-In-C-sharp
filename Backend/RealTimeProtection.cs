using System;
using System.IO;
using System.Threading.Tasks;

namespace Page_Navigation_App.Backend
{
    /// <summary>
    /// Provides lightweight real-time protection by monitoring user folders for new or changed files.
    /// </summary>
    public class RealTimeProtection : IDisposable
    {
        private FileSystemWatcher _watcher;
        private bool _enabled;
        public event Action<string> ThreatDetected;

        public RealTimeProtection(string folderToWatch)
        {
            _watcher = new FileSystemWatcher(folderToWatch)
            {
                EnableRaisingEvents = false,
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
            };
            _watcher.Created += OnChanged;
            _watcher.Changed += OnChanged;
        }

        public void Start()
        {
            if (!_enabled)
            {
                _watcher.EnableRaisingEvents = true;
                _enabled = true;
            }
        }

        public void Stop()
        {
            if (_enabled)
            {
                _watcher.EnableRaisingEvents = false;
                _enabled = false;
            }
        }

        private async void OnChanged(object sender, FileSystemEventArgs e)
        {
            await Task.Delay(200); // Debounce
            try
            {
                if (File.Exists(e.FullPath))
                {
                    if (HeuristicScanner.IsSuspicious(e.FullPath, out string reason))
                    {
                        // Quarantine the file
                        string quarantinePath = QuarantineManager.QuarantineFile(e.FullPath);
                        // Log the event
                        ScanLogger.LogScan("Real-Time Protection (Heuristic)", new System.Collections.Generic.List<string> { quarantinePath });
                        // Notify via event
                        ThreatDetected?.Invoke(quarantinePath);
                    }
                }
            }
            catch { /* Ignore errors for locked/inaccessible files */ }
        }

        private Task<bool> LightweightScanAsync(string filePath)
        {
            // TODO: Replace with actual scan logic (signature check, etc.)
            // For demo, return false (not a threat)
            return Task.FromResult(false);
        }

        public void Dispose()
        {
            Stop();
            _watcher?.Dispose();
        }
    }
}
