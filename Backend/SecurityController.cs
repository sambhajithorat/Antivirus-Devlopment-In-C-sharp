using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Page_Navigation_App.Backend.Database;
using Page_Navigation_App.Backend.Models;
using Page_Navigation_App.Backend.Scanner;

namespace Page_Navigation_App.Backend
{
    public class SecurityController
    {
        private readonly SignatureDatabase _signatureDatabase;
        private readonly FileScanner _fileScanner;

        public bool IsScanning { get; internal set; }

        // Events for UI notifications
        public event EventHandler<int> ScanProgressUpdated;
        public event EventHandler<ScanResult> FileScanned;
        public event EventHandler<ScanResult> ThreatDetected;
        public event EventHandler<List<ScanResult>> ScanCompleted;

        // Accept the instance via constructor!
        public SecurityController(SignatureDatabase signatureDatabase)
        {
            _signatureDatabase = signatureDatabase ?? throw new ArgumentNullException(nameof(signatureDatabase));
            _fileScanner = new FileScanner(_signatureDatabase);

            // Wire up event handlers
            _fileScanner.FileScanned += OnFileScanned;
            _fileScanner.ThreatDetected += OnThreatDetected;
            _fileScanner.ScanProgressUpdated += OnScanProgressUpdated;
            _fileScanner.ScanCompleted += OnScanCompleted;
        }

        // Scan an entire directory (used for custom/target sweep)
        public async Task<ScanSession> ScanDirectoryAsync(string directoryPath, bool includeSubdirectories, CancellationToken cancellationToken = default)
        {
            return await _fileScanner.ScanDirectoryAsync(directoryPath, includeSubdirectories, cancellationToken);
        }

        // Scan an entire drive (could be used for full system scan)
        public async Task<ScanSession> ScanDriveAsync(string driveLetter, bool includeSubdirectories = true, CancellationToken cancellationToken = default)
        {
            return await _fileScanner.ScanDriveAsync(driveLetter, includeSubdirectories, cancellationToken);
        }

        // Scan a single file (used in parallel for full system scan)
        public async Task<ScanResult> ScanFileAsync(string filePath)
        {
            return await _fileScanner.ScanFileAsync(filePath);
        }

        // Cancel any ongoing scan
        public void CancelScan()
        {
            _fileScanner.CancelScan();
        }

        // Retrieve threats found in the last scan
        public List<ScanResult> GetDetectedThreats()
        {
            return _fileScanner.GetDetectedThreats();
        }

        // Clear the list of detected threats
        public void ClearDetectedThreats()
        {
            _fileScanner.ClearDetectedThreats();
        }

        // Event forwarding methods
        private void OnFileScanned(object sender, ScanResult e)
        {
            FileScanned?.Invoke(this, e);
        }

        private void OnThreatDetected(object sender, ScanResult e)
        {
            ThreatDetected?.Invoke(this, e);
        }

        private void OnScanProgressUpdated(object sender, int e)
        {
            ScanProgressUpdated?.Invoke(this, e);
        }

        private void OnScanCompleted(object sender, List<ScanResult> e)
        {
            ScanCompleted?.Invoke(this, e);
        }

        // Signature database methods
        public async Task UpdateSignaturesAsync()
        {
            await _signatureDatabase.RefreshSignaturesFromDatabase();
        }

        public int GetSignatureCount()
        {
            return _signatureDatabase.SignaturesCount;
        }

        public DateTime GetLastUpdateTime()
        {
            return _signatureDatabase.LastUpdateTime;
        }

        // Add this method for async DB initialization
        public async Task InitializeSignatureDatabaseAsync()
        {
            await _signatureDatabase.InitializeAsync();
        }
    }
}