using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace Page_Navigation_App.Backend.Helpers
{
    public static class SystemSweepHelper
    {
        // Progress callback: (filesFound, currentDir)
        public static async Task<List<string>> EnumerateAllFilesAsync(
            IProgress<(int, string)> progress = null,
            CancellationToken cancellationToken = default)
        {
            // Use ConcurrentBag for thread-safe collection
            var files = new ConcurrentBag<string>();
            var reportedCount = 0;
            var lastReportTime = DateTime.Now;

            await Task.Run(async () =>
            {
                // Get all drives in parallel
                var drives = DriveInfo.GetDrives();
                var validDrives = new List<DriveInfo>();
                
                foreach (var drive in drives)
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;
                        
                    if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                    {
                        validDrives.Add(drive);
                    }
                }
                
                // Debug: Show which drives are being scanned
                // No debug popups in production. Silently proceed with valid drives.

                // Process drives in parallel for faster enumeration
                var tasks = new List<Task>();
                foreach (var drive in validDrives)
                {
                    tasks.Add(Task.Run(() => 
                        EnumerateFilesSafe(
                            drive.RootDirectory.FullName, 
                            files, 
                            (count, path) => 
                            {
                                // Throttle progress reports to avoid UI overload
                                var now = DateTime.Now;
                                if ((now - lastReportTime).TotalMilliseconds > 250)
                                {
                                    Interlocked.Exchange(ref reportedCount, files.Count);
                                    lastReportTime = now;
                                    progress?.Report((reportedCount, path));
                                }
                            }, 
                            cancellationToken), 
                        cancellationToken));
                }
                
                await Task.WhenAll(tasks);
            }, cancellationToken);

            // Final report with accurate count
            progress?.Report((files.Count, "Complete"));
            
            // Return as regular list
            return new List<string>(files);
        }

        private static void EnumerateFilesSafe(
            string path, 
            ConcurrentBag<string> files,
            Action<int, string> progressCallback,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return;
                
            try
            {
                // Allow scanning of drive root directories even if marked as System or Hidden
                var dirInfo = new DirectoryInfo(path);
                bool isDriveRoot = dirInfo.Parent == null;
                if (!isDriveRoot && ((dirInfo.Attributes & FileAttributes.System) == FileAttributes.System ||
                    (dirInfo.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden))
                {
                    // Silently skip hidden/system directories
                    return;
                }
                
                // Get all files in current directory and add them
                string[] dirFiles = null;
                try
                {
                    dirFiles = Directory.GetFiles(path);
                }
                catch { /* Silently ignore file access errors */ }
                
                if (dirFiles != null)
                {
                    foreach (var file in dirFiles)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            return;
                            
                        files.Add(file);
                        progressCallback(files.Count, path);
                    }
                }

                // Get all subdirectories
                string[] subDirs = null;
                try
                {
                    subDirs = Directory.GetDirectories(path);
                }
                catch { /* Silently ignore directory access errors */ }
                
                if (subDirs != null)
                {
                    // Use parallel processing for better performance on multicore systems
                    if (subDirs.Length > 10)
                    {
                        Parallel.ForEach(
                            subDirs,
                            new ParallelOptions { CancellationToken = cancellationToken, MaxDegreeOfParallelism = Environment.ProcessorCount },
                            dir => EnumerateFilesSafe(dir, files, progressCallback, cancellationToken)
                        );
                    }
                    else
                    {
                        // Use sequential processing for small number of subdirectories
                        foreach (var dir in subDirs)
                        {
                            if (cancellationToken.IsCancellationRequested)
                                return;
                                
                            EnumerateFilesSafe(dir, files, progressCallback, cancellationToken);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Silently ignore file system errors
            }
        }
    }
}
