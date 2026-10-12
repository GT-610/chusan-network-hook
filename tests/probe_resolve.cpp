// A/B probe that reports exactly what resolve_network_interface() concludes, by
// loading the hook DLL into this process and reading its log output. The hook writes
// its startup banner (including every INTERFACE action line) to the log file next to
// the DLL, so the probe just enables file logging and prints the tail of that file.
//
// This is the same code path chusanApp.exe takes, minus the game's own socket work,
// so it isolates the DLL's interface resolution from everything else.
//
// Build (x86, matching chusanApp.exe):
//   cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS probe_resolve.cpp
//      /link ws2_32.lib iphlpapi.lib
//
// Usage: probe_resolve.exe <hook dll> [interfaceAddress]

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

namespace {

void write_ini(const char *dll_path, const char *interface_address) {
    char directory[MAX_PATH] = {};
    _snprintf_s(directory, sizeof(directory), _TRUNCATE, "%s", dll_path);
    char *slash = strrchr(directory, '\\');
    if (slash != nullptr) *slash = '\0';
    char ini[MAX_PATH] = {};
    _snprintf_s(ini, sizeof(ini), _TRUNCATE, "%s\\network_hook.ini", directory);
    FILE *f = nullptr;
    if (fopen_s(&f, ini, "w") != 0 || f == nullptr) return;
    fprintf(f, "[network]\nenable=1\ninterfaceAddress=%s\n", interface_address);
    fprintf(f, "forceLimitedBroadcast=1\nforceTcpSource=1\nstrict=1\n");
    fprintf(f, "[lanInstall]\nenable=1\n");
    fprintf(f, "[log]\nenable=1\ndetailed=1\nwriteFile=1\n");
    fclose(f);
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hook dll> [interfaceAddress]\n", argv[0]);
        return 2;
    }
    const char *interface_address = argc > 2 ? argv[2] : "192.168.139.17";
    write_ini(argv[1], interface_address);

    // Remove a stale log so we only read what this run produced.
    char directory[MAX_PATH] = {};
    _snprintf_s(directory, sizeof(directory), _TRUNCATE, "%s", argv[1]);
    char *slash = strrchr(directory, '\\');
    if (slash != nullptr) *slash = '\0';
    char log_directory[MAX_PATH] = {};
    _snprintf_s(log_directory, sizeof(log_directory), _TRUNCATE, "%s\\network_hook_logs", directory);

    HMODULE dll = LoadLibraryA(argv[1]);
    if (dll == nullptr) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    printf("loaded %s (interfaceAddress=%s)\n", argv[1], interface_address);
    fflush(stdout);

    // The hook initializes on a worker thread; give it time to finish.
    for (int i = 0; i < 40; ++i) {
        Sleep(50);
        char pattern[MAX_PATH] = {};
        _snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s\\network_hook_*.log", log_directory);
        WIN32_FIND_DATAA found = {};
        HANDLE search = FindFirstFileA(pattern, &found);
        if (search != INVALID_HANDLE_VALUE) {
            FindClose(search);
            break;
        }
    }
    Sleep(300);

    // Print the newest log file.
    char pattern[MAX_PATH] = {};
    _snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s\\network_hook_*.log", log_directory);
    WIN32_FIND_DATAA found = {};
    HANDLE search = FindFirstFileA(pattern, &found);
    char newest[MAX_PATH] = {};
    FILETIME best = {};
    if (search != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH] = {};
            _snprintf_s(full, sizeof(full), _TRUNCATE, "%s\\%s", log_directory, found.cFileName);
            HANDLE file = CreateFileA(full, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                FILETIME written = {};
                if (GetFileTime(file, nullptr, nullptr, &written) &&
                    CompareFileTime(&written, &best) > 0) {
                    best = written;
                    strcpy_s(newest, sizeof(newest), full);
                }
                CloseHandle(file);
            }
        } while (FindNextFileA(search, &found));
        FindClose(search);
    }

    if (newest[0] == '\0') {
        fprintf(stderr, "no hook log produced\n");
        FreeLibrary(dll);
        return 1;
    }

    FILE *f = nullptr;
    if (fopen_s(&f, newest, "r") == 0 && f != nullptr) {
        printf("--- %s ---\n", newest);
        char line[4096] = {};
        while (fgets(line, sizeof(line), f) != nullptr) printf("%s", line);
        fclose(f);
    }
    FreeLibrary(dll);
    return 0;
}
