// Secure File Scanner

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <sqlite3.h>
#include <ctime>
#include <stdexcept>
#include <regex>
#include <queue>
#include <condition_variable>
#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <magic.h> // libmagic for MIME type

namespace fs = std::filesystem;

std::mutex logMutex;
std::mutex dbMutex;
std::mutex queueMutex;
std::condition_variable cv;
std::queue<fs::path> fileQueue;
bool done = false;

struct ScanResult {
    std::string filePath;
    std::string status;
    std::string sha256;
    std::string md5;
    std::string fileType;
    std::string mimeType;
    std::string signature;
};

std::vector<ScanResult> scanResults;
std::vector<fs::path> criticalDirectories = {
    "C:\\Users\\%USERNAME%\\Documents",
    "C:\\Users\\%USERNAME%\\Downloads",
    "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Windows\\System32",
    "C:\\Program Files (x86)",
    "C:\\Program Files",
    "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\INetCache",
    "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files"
};

// Function to expand user directory placeholders
fs::path expandPath(const std::string& path) {
    std::string username = "DefaultUser"; // Default username
    char* envUsername = nullptr;
    size_t len;
    if (_dupenv_s(&envUsername, &len, "USERNAME") == 0 && envUsername != nullptr) {
        username = envUsername;
        std::free(envUsername);
    }
    return fs::path(std::regex_replace(path, std::regex("%USERNAME%"), username));
}

// Function to normalize and verify paths securely
fs::path normalizeAndVerifyPath(const fs::path& path, const fs::path& baseDir) {
    fs::path normalizedPath;
    fs::path normalizedBaseDir;

    try {
        normalizedPath = fs::canonical(path);
        normalizedBaseDir = fs::canonical(baseDir);

        // Prevent path traversal by ensuring the normalized path starts with the base directory
        if (!normalizedPath.string().starts_with(normalizedBaseDir.string())) {
            throw std::runtime_error("Path traversal detected.");
        }
    } catch (const fs::filesystem_error& e) {
        // Log the detailed error internally and throw a generic runtime error
        logError("Filesystem error: " + std::string(e.what()));
        throw std::runtime_error("Invalid path detected.");
    }

    return normalizedPath;
}

// Function to compute SHA-256 hash of a file
std::string sha256(const fs::path& filePath) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file.");
    }
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Function to compute MD5 hash of a file
std::string md5(const fs::path& filePath) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file.");
    }
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&md5, buffer, file.gcount());
    }
    MD5_Update(&md5, buffer, file.gcount());
    MD5_Final(hash, &md5);
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Function to get file type
std::string getFileType(const fs::path& filePath) {
    std::string fileType = "Unknown";
    try {
        fileType = fs::is_directory(filePath) ? "Directory" : "File";
    } catch (const fs::filesystem_error& e) {
        logError("Filesystem error: " + std::string(e.what()));
    }
    return fileType;
}

// Function to get MIME type using libmagic
std::string getMimeType(const fs::path& filePath) {
    magic_t magic = magic_open(MAGIC_MIME_TYPE);
    if (magic == nullptr) {
        throw std::runtime_error("Failed to initialize libmagic.");
    }
    if (magic_load(magic, nullptr) != 0) {
        magic_close(magic);
        throw std::runtime_error("Failed to load magic database.");
    }
    const char* mimeType = magic_file(magic, filePath.string().c_str());
    std::string mimeTypeStr = mimeType ? mimeType : "Unknown";
    magic_close(magic);
    return mimeTypeStr;
}

// Function to check if a file is infected by comparing hashes with the database
bool isFileInfected(const std::string& sha256Hash, const std::string& md5Hash, sqlite3* db, ScanResult& result) {
    std::lock_guard<std::mutex> guard(dbMutex);
    sqlite3_stmt* stmt;
    std::string query = "SELECT sha256, md5, file_type, mime_type, signature FROM virus_signatures WHERE sha256 = ? OR md5 = ?;";
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare SQL statement.");
    }
    sqlite3_bind_text(stmt, 1, sha256Hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, md5Hash.c_str(), -1, SQLITE_STATIC);
    bool infected = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result.sha256 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        result.md5 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        result.fileType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        result.mimeType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        result.signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        infected = true;
    }
    sqlite3_finalize(stmt);
    return infected;
}

// Function to log errors securely
void logError(const std::string& errorMessage) {
    std::lock_guard<std::mutex> guard(logMutex);
    std::ofstream logFile("error_log.txt", std::ios::app);
    std::time_t now = std::time(nullptr);
    logFile << std::ctime(&now) << " - " << errorMessage << std::endl;
}

// Function to scan a single file
void scanFile(sqlite3* db) {
    while (true) {
        fs::path filePath;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            cv.wait(lock, [] { return !fileQueue.empty() || done; });

            if (fileQueue.empty() && done) break;

            filePath = fileQueue.front();
            fileQueue.pop();
        }

        try {
            std::string sha256Hash = sha256(filePath);
            std::string md5Hash = md5(filePath);
            std::string fileType = getFileType(filePath);
            std::string mimeType = getMimeType(filePath);
            ScanResult result = {filePath.string(), "Clean", sha256Hash, md5Hash, fileType, mimeType, ""};
            bool infected = isFileInfected(sha256Hash, md5Hash, db, result);
            result.status = infected ? "Infected" : "Clean";
            {
                std::lock_guard<std::mutex> guard(logMutex);
                scanResults.push_back(result);
            }
            std::cout << result.filePath << " - " << result.status << std::endl;
            if (infected) {
                std::cout << "SHA256: " << result.sha256 << std::endl;
                std::cout << "MD5: " << result.md5 << std::endl;
                std::cout << "File Type: " << result.fileType << std::endl;
                std::cout << "MIME Type: " << result.mimeType << std::endl;
                std::cout << "Signature: " << result.signature << std::endl;
            }
        } catch (const std::exception& ex) {
            logError(ex.what());
            std::cerr << "An error occurred during the scan. Please try again later or contact support." << std::endl;
            std::lock_guard<std::mutex> guard(logMutex);
            scanResults.push_back({filePath.string(), "Error"});
        }
    }
}

// Function to scan a directory recursively
void scanDirectory(const fs::path& directory) {
    for (const auto& entry : fs::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            fs::path normalizedPath = normalizeAndVerifyPath(entry.path(), directory);
            std::lock_guard<std::mutex> lock(queueMutex);
            fileQueue.push(normalizedPath);
            cv.notify_one();
        }
    }
}

// Function to save scan results to a log file
void saveLog() {
    std::ofstream logFile("scan_log.txt");
    for (const auto& result : scanResults) {
        logFile << result.filePath << " - " << result.status << std::endl;
        if (result.status == "Infected") {
            logFile << "SHA256: " << result.sha256 << std::endl;
            logFile << "MD5: " << result.md5 << std::endl;
            logFile << "File Type: " << result.fileType << std::endl;
            logFile << "MIME Type: " << result.mimeType << std::endl;
            logFile << "Signature: " << result.signature << std::endl;
        }
    }
}

// Function to scan registry keys
void scanRegistryKeys(HKEY hKey, const std::string& subKey) {
    HKEY hSubKey;
    if (RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
        char keyName[256];
        DWORD keyNameSize = sizeof(keyName);
        DWORD index = 0;

        while (RegEnumKeyEx(hSubKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::string fullSubKey = subKey + "\\" + keyName;
            std::cout << "Scanning registry key: " << fullSubKey << std::endl;

            // Recursively scan sub-keys
            scanRegistryKeys(hSubKey, keyName);

            keyNameSize = sizeof(keyName);
            index++;
        }

        RegCloseKey(hSubKey);
    } else {
        logError("Failed to open registry key: " + subKey);
    }
}

// Function to scan active processes
void scanActiveProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        logError("Failed to create process snapshot.");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        logError("Failed to retrieve first process.");
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        std::wcout << L"Scanning process: " << pe32.szExeFile << std::endl;

        // Additional scanning logic can be added here

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main() {
    std::cout << "Admin privileges are required to access certain files. Please restart the program with admin rights." << std::endl;

    sqlite3* db;
    if (sqlite3_open("virus_signatures.db", &db) != SQLITE_OK) {
        std::cerr << "An error occurred during the scan. Please try again later or contact support." << std::endl;
        logError("Failed to open database.");
        return 1;
    }

    std::vector<std::thread> threads;
    const int numThreads = std::thread::hardware_concurrency();

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(scanFile, db);
    }

    for (const auto& directory : criticalDirectories) {
        try {
            fs::path expandedDir = expandPath(directory);
            scanDirectory(expandedDir);
        } catch (const std::exception& ex) {
            logError(ex.what());
            std::cerr << "An error occurred during the scan. Please try again later or contact support." << std::endl;
        }
    }

    // Scan registry keys (example: HKEY_LOCAL_MACHINE\Software)
    scanRegistryKeys(HKEY_LOCAL_MACHINE, "Software");

    // Scan active processes
    scanActiveProcesses();

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        done = true;
    }
    cv.notify_all();

    for (auto& thread : threads) {
        thread.join();
    }

    saveLog();
    sqlite3_close(db);
    std::cout << "Scanning completed." << std::endl;
    return 0;
}