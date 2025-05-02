using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Page_Navigation_App.Backend.Scanner;
using Page_Navigation_App.Backend.Database;

namespace Page_Navigation_App.Backend
{
    public class USBWatcher : IDisposable
    {
        // Event that will be triggered when a USB device is detected
        public event Action<string> UsbDeviceDetected;
        
        // Management event watcher for device insertions
        private ManagementEventWatcher insertWatcher;
        
        // Fallback polling mechanism
        private CancellationTokenSource pollingCts;
        private bool pollingActive;
        private List<string> knownDrives = new List<string>();
        
        // Scanning components
        private readonly FileScanner _fileScanner;
        private readonly SignatureDatabase _signatureDatabase;
        
        public USBWatcher()
        {
            _signatureDatabase = new SignatureDatabase();
            _fileScanner = new FileScanner(_signatureDatabase);
        }

        public void StartWatching()
        {
            // Try to set up WMI event watching
            try
            {
                Debug.WriteLine("USBWatcher: Starting WMI watcher for USB drives");
                WqlEventQuery query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2");
                insertWatcher = new ManagementEventWatcher(query);
                insertWatcher.EventArrived += DeviceInsertedEvent;
                insertWatcher.Start();
                Debug.WriteLine("USBWatcher: WMI watcher started.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"USBWatcher: Failed to start WMI watcher: {ex.Message}");
                // Error will be shown in the UI status instead of a message box
            }

            // Always start polling as a backup (in case WMI doesn't fire)
            pollingCts = new CancellationTokenSource();
            pollingActive = true;
            knownDrives = DriveInfo.GetDrives()
                .Where(d => d.IsReady && d.DriveType == DriveType.Removable)
                .Select(d => d.Name)
                .ToList();
            
            Task.Run(() => PollForUsbDrives(pollingCts.Token));
            
            // Initial detection of any already connected devices
            foreach (var drive in knownDrives)
            {
                NotifyUsbDetected(drive);
            }
        }

        public void StopWatching()
        {
            try
            {
                if (insertWatcher != null)
                {
                    insertWatcher.Stop();
                    insertWatcher.EventArrived -= DeviceInsertedEvent;
                    insertWatcher.Dispose();
                    insertWatcher = null;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error stopping USB watcher: {ex.Message}");
            }
            
            pollingActive = false;
            pollingCts?.Cancel();
            pollingCts?.Dispose();
            pollingCts = null;
        }

        private void DeviceInsertedEvent(object sender, EventArrivedEventArgs e)
        {
            try
            {
                Debug.WriteLine("DeviceInsertedEvent triggered!");
                string driveName = e.NewEvent.Properties["DriveName"]?.Value?.ToString();

                if (!string.IsNullOrEmpty(driveName))
                {
                    // Make sure the drive exists and is ready
                    var driveInfo = new DriveInfo(driveName);
                    if (driveInfo.IsReady && driveInfo.DriveType == DriveType.Removable)
                    {
                        NotifyUsbDetected(driveName);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exception in DeviceInsertedEvent: {ex.Message}");
            }
        }

        // Polling fallback if WMI doesn't work
        private void PollForUsbDrives(CancellationToken token)
        {
            while (pollingActive && !token.IsCancellationRequested)
            {
                try
                {
                    var currentDrives = DriveInfo.GetDrives()
                        .Where(d => d.IsReady && d.DriveType == DriveType.Removable)
                        .Select(d => d.Name)
                        .ToList();

                    // Check for new drives
                    var newDrives = currentDrives.Except(knownDrives).ToList();
                    foreach (var drive in newDrives)
                    {
                        Debug.WriteLine($"Polling detected new USB: {drive}");
                        NotifyUsbDetected(drive);
                    }
                    
                    // Update our list of known drives
                    knownDrives = currentDrives;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"USBWatcher Polling error: {ex.Message}");
                }
                
                // Sleep for a short time before polling again
                Thread.Sleep(2000); // Poll every 2 seconds
            }
        }

        private void NotifyUsbDetected(string driveName)
        {
            try
            {
                Debug.WriteLine($"USB device detected: {driveName}");
                
                // Make sure we're not passing an empty or null string
                if (string.IsNullOrWhiteSpace(driveName))
                    return;
                
                // Make sure it ends with a backslash for consistency
                if (!driveName.EndsWith("\\"))
                    driveName += "\\";
                    
                // Notify the ViewModel about the new USB device
                Application.Current?.Dispatcher?.Invoke(() => 
                {
                    UsbDeviceDetected?.Invoke(driveName);
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in NotifyUsbDetected: {ex.Message}");
            }
        }

        // IDisposable implementation
        public void Dispose()
        {
            StopWatching();
        }
    }
}