using System;
using System.IO;

public static class QuarantineManager
{
    private static readonly string quarantineFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        "AntivirusQuarantine");

    static QuarantineManager()
    {
        if (!Directory.Exists(quarantineFolder))
            Directory.CreateDirectory(quarantineFolder);
    }

    /// <summary>
    /// Moves the specified file to the quarantine folder, renaming it with a timestamp and .quarantined extension.
    /// Returns the new quarantine path.
    /// </summary>
    public static string QuarantineFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File to quarantine not found.", filePath);

        string fileName = Path.GetFileName(filePath);
        string quarantinePath = Path.Combine(
            quarantineFolder,
            $"{fileName}_{DateTime.Now:yyyyMMddHHmmss}.quarantined"
        );

        // Move the file to quarantine
        File.Move(filePath, quarantinePath);

        // Save the original path in a metadata file
        string metaPath = quarantinePath + ".meta";
        File.WriteAllText(metaPath, filePath);

        return quarantinePath;
    }

    /// <summary>
    /// Gets the original file path for a quarantined file (if available).
    /// </summary>
    public static string GetOriginalPath(string quarantineFilePath)
    {
        string metaPath = quarantineFilePath + ".meta";
        if (File.Exists(metaPath))
            return File.ReadAllText(metaPath);
        return null;
    }

    /// <summary>
    /// Gets the path to the quarantine folder.
    /// </summary>
    public static string GetQuarantineFolder()
    {
        return quarantineFolder;
    }
}
