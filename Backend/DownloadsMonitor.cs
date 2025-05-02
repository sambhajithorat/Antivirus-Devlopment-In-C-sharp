using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Collections.Generic;
using System.Security.Cryptography;

public class DownloadsMonitor
{
    private FileSystemWatcher watcher;
    private string downloadsPath;
    private HashSet<string> malwareDb;

    public DownloadsMonitor()
    {
        downloadsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
        LoadMalwareDatabase();
    }

    public void StartWatching()
    {
        if (!Directory.Exists(downloadsPath))
            return;

        watcher = new FileSystemWatcher(downloadsPath);
        watcher.Created += OnNewFileCreated;
        watcher.EnableRaisingEvents = true;
    }

    public void StopWatching()
    {
        if (watcher != null)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
    }

    private void OnNewFileCreated(object sender, FileSystemEventArgs e)
    {
        // Run scan in the background
        Task.Run(() => ScanFileWithDatabase(e.FullPath));
    }

    private void LoadMalwareDatabase()
    {
        malwareDb = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "malware_db.txt");
        if (File.Exists(dbPath))
        {
            foreach (var line in File.ReadAllLines(dbPath))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    malwareDb.Add(trimmed);
            }
        }
    }

    private void ScanFileWithDatabase(string filePath)
    {
        try
        {
            // Wait for file to be ready (avoid file lock issues)
            for (int i = 0; i < 5; i++)
            {
                if (File.Exists(filePath))
                {
                    try
                    {
                        using (FileStream stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            break;
                        }
                    }
                    catch (IOException)
                    {
                        Task.Delay(500).Wait();
                    }
                }
            }

            // Calculate hash (e.g., SHA256)
            string hash = ComputeSHA256(filePath);

            bool isThreat = malwareDb.Contains(hash);

            if (isThreat)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(
                        $"Threat detected in downloaded file:\n{filePath}\nSHA256: {hash}",
                        "Downloads Monitor",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                });
            }
        }
        catch (Exception ex)
        {
            // Optionally log errors
        }
    }

    // SHA256 hash calculation
    private string ComputeSHA256(string filePath)
    {
        using (FileStream stream = File.OpenRead(filePath))
        using (SHA256 sha = SHA256.Create())
        {
            byte[] hashBytes = sha.ComputeHash(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
    }
}