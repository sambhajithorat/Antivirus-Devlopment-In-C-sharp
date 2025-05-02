using System;
using System.Management;

public static class SystemSpecHelper
{
    // Returns the number of logical processors (cores/threads)
    public static int GetLogicalProcessorCount()
    {
        return Environment.ProcessorCount;
    }

    // Returns total physical memory (RAM) in GB
    public static int GetTotalMemoryInGB()
    {
        try
        {
            // Works on Windows with System.Management
            using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
            {
                foreach (var obj in searcher.Get())
                {
                    double bytes = Convert.ToDouble(obj["TotalPhysicalMemory"]);
                    return (int)(bytes / (1024 * 1024 * 1024));
                }
            }
        }
        catch { }
        // Fallback: assume 4GB if unable to read
        return 4;
    }

    // Suggests a batch size based on system specs
    public static int GetRecommendedBatchSize()
    {
        int cores = GetLogicalProcessorCount();
        int ramGB = GetTotalMemoryInGB();

        // Conservative logic: never exceed cores, and be gentler on low RAM
        if (ramGB < 4) return Math.Min(2, cores);
        if (ramGB < 8) return Math.Min(4, cores);
        if (ramGB < 16) return Math.Min(6, cores);
        return Math.Min(8, cores);
    }
}