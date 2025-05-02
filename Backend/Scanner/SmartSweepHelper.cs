using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace Page_Navigation_App.Backend.Scanner
{
    public static class SmartSweepHelper
    {
        public static IEnumerable<string> GetSmartScanPaths()
        {
            var paths = new List<string>();

            // System folders
            paths.Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32"));
            paths.Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\SysWOW64"));
            paths.Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\Temp"));
            paths.Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\Tasks"));
            paths.Add(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\Prefetch"));

            // User profile folders
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            paths.Add(Path.Combine(userProfile, @"AppData\Roaming"));
            paths.Add(Path.Combine(userProfile, @"AppData\Local\Temp"));
            paths.Add(Path.Combine(userProfile, @"AppData\LocalLow"));
            paths.Add(Path.Combine(userProfile, @"AppData\Local\Microsoft\Windows\INetCache"));
            paths.Add(Path.Combine(userProfile, @"AppData\Local\Microsoft\Windows\Temporary Internet Files"));
            paths.Add(Path.Combine(userProfile, "Downloads"));
            paths.Add(Path.Combine(userProfile, "Desktop"));
            paths.Add(Path.Combine(userProfile, "Documents"));

            // Startup folders
            paths.Add(Environment.ExpandEnvironmentVariables(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"));

            // Program Files
            paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            // Browser cache (Chrome, Firefox, Edge)
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            paths.Add(Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Cache"));
            paths.Add(Path.Combine(appData, @"Mozilla\Firefox\Profiles"));
            paths.Add(Path.Combine(localAppData, @"Microsoft\Edge\User Data\Default\Cache"));

            return paths.Distinct().Where(Directory.Exists);
        }

        public static IEnumerable<string> GetStartupRegistryPaths()
        {
            var startupPaths = new List<string>();
            // HKCU Run
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName) as string;
                        if (!string.IsNullOrEmpty(value))
                        {
                            string exePath = value.Trim('"').Split(' ').FirstOrDefault();
                            if (File.Exists(exePath))
                                startupPaths.Add(exePath);
                        }
                    }
                }
            }
            // HKLM Run
            using (var key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName) as string;
                        if (!string.IsNullOrEmpty(value))
                        {
                            string exePath = value.Trim('"').Split(' ').FirstOrDefault();
                            if (File.Exists(exePath))
                                startupPaths.Add(exePath);
                        }
                    }
                }
            }
            return startupPaths;
        }

        public static IEnumerable<string> GetRunningProcessPaths()
        {
            var processPaths = new List<string>();
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (!string.IsNullOrEmpty(proc.MainModule?.FileName) && File.Exists(proc.MainModule.FileName))
                        processPaths.Add(proc.MainModule.FileName);
                }
                catch { /* Access denied or system process */ }
            }
            return processPaths.Distinct();
        }

        /// <summary>
        /// Enumerate files in a directory up to a certain depth, filtering by allowed extensions.
        /// </summary>
        public static IEnumerable<string> EnumerateFilesSmart(string root, int maxDepth, HashSet<string> allowedExtensions)
        {
            var dirs = new Queue<(string path, int depth)>();
            dirs.Enqueue((root, 0));
            while (dirs.Count > 0)
            {
                var (current, depth) = dirs.Dequeue();
                if (depth > maxDepth) continue;

                List<string> files = null;
                try
                {
                    files = Directory.GetFiles(current).ToList();
                }
                catch { /* skip inaccessible dirs */ }

                if (files != null)
                {
                    foreach (var file in files)
                    {
                        if (allowedExtensions.Contains(Path.GetExtension(file)))
                            yield return file;
                    }
                }

                if (depth < maxDepth)
                {
                    string[] subDirs = null;
                    try
                    {
                        subDirs = Directory.GetDirectories(current);
                    }
                    catch { }
                    if (subDirs != null)
                    {
                        foreach (var dir in subDirs)
                            dirs.Enqueue((dir, depth + 1));
                    }
                }
            }
        }
    }
}