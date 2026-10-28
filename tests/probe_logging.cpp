// Probe: what the log says with detailed logging off, and what it costs with it on.
//
// Two defects are covered, both reported from an in-game session:
//
//   * `[log] detailed=0` used to silence nearly everything. Start-up identity - which
//     process this is, whether the hooks installed, which interface carries the LAN, where
//     the log lives - is not diagnostic detail; it is the answer to "is this DLL working",
//     and `chusanApp.exe` has no console to print it to. The status line also skipped the
//     file, so a session could leave a log with no record of having started at all.
//
//   * `[log] detailed=1` with `[lanInstall] enable=1` turned amdaemon's LAN Install polling
//     loop (about one poll per millisecond) into one LAN_VIRT line per poll, which buried
//     every other line and spent the session flushing to disk. Repeats are folded into a
//     rate now, and this case asserts the fold: thousands of virtualised calls must not
//     become thousands of lines, while the first call of each kind has to stay visible and
//     the folded count has to be reported.
//
// The two cases need separate processes: the hook reads network_hook.ini from its own
// directory in DllMain, and two copies of it cannot coexist in one process. The parent
// prepares a directory per case and re-executes itself into it, the same way
// probe_ownership does.
//
// Usage: probe_logging <hook.dll>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

static int fail(const char *what, DWORD error) {
    fprintf(stderr, "FAIL: %s (%lu)\n", what, error);
    return 1;
}

static int fail_text(const char *what) {
    fprintf(stderr, "FAIL: %s\n", what);
    return 1;
}

// Below this, the virtualised ports answer WSAEWOULDBLOCK by design, so an error return is
// the expected result and not a failure to report.
static bool wait_until_hooked(int seconds) {
    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)seconds * 1000;
    for (;;) {
        SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp != INVALID_SOCKET) {
            sockaddr_in beacon = {};
            beacon.sin_family = AF_INET;
            beacon.sin_port = htons(40112);
            beacon.sin_addr.s_addr = INADDR_BROADCAST;
            const char byte = 0;
            const int sent = sendto(udp, &byte, 1, 0,
                reinterpret_cast<const sockaddr *>(&beacon), sizeof(beacon));
            closesocket(udp);
            if (sent == 1) return true;
        }
        if (GetTickCount64() >= deadline) return false;
        Sleep(50);
    }
}

// The shape amdaemon polls in: a non-blocking listener, a non-blocking reader on the same
// socket, and a beacon, all on the same tick. Five thousand of these used to be five
// thousand log lines.
static int run_virtual_flood() {
    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp == INVALID_SOCKET) return fail("sync socket", WSAGetLastError());
    sockaddr_in sync = {};
    sync.sin_family = AF_INET;
    sync.sin_port = htons(40110);
    sync.sin_addr.s_addr = INADDR_ANY;
    if (bind(tcp, reinterpret_cast<const sockaddr *>(&sync), sizeof(sync)) == SOCKET_ERROR) {
        const DWORD error = WSAGetLastError();
        closesocket(tcp);
        return fail("virtual TCP bind", error);
    }
    if (listen(tcp, 4) == SOCKET_ERROR) {
        const DWORD error = WSAGetLastError();
        closesocket(tcp);
        return fail("virtual TCP listen", error);
    }
    u_long nonblocking = 1;
    if (ioctlsocket(tcp, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        const DWORD error = WSAGetLastError();
        closesocket(tcp);
        return fail("sync non-blocking", error);
    }

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        closesocket(tcp);
        return fail("beacon socket", WSAGetLastError());
    }
    sockaddr_in beacon = {};
    beacon.sin_family = AF_INET;
    beacon.sin_port = htons(40112);
    beacon.sin_addr.s_addr = INADDR_BROADCAST;

    char buffer[64] = {};
    for (int i = 0; i < 2000; ++i) {
        const SOCKET accepted = accept(tcp, nullptr, nullptr);
        if (accepted != INVALID_SOCKET) closesocket(accepted);
        if (recv(tcp, buffer, (int)sizeof(buffer), 0) != SOCKET_ERROR) {
            closesocket(udp);
            closesocket(tcp);
            return fail_text("recv on a virtualised sync socket returned data");
        }
        if (i < 1000 &&
            sendto(udp, buffer, 1, 0, reinterpret_cast<const sockaddr *>(&beacon),
                sizeof(beacon)) != 1) {
            const DWORD error = WSAGetLastError();
            closesocket(udp);
            closesocket(tcp);
            return fail("virtual beacon send", error);
        }
    }

    // The fold interval has to elapse before the next line can carry a count; these calls
    // are the ones that report how many were absorbed.
    Sleep(1100);
    for (int i = 0; i < 5; ++i) {
        const SOCKET accepted = accept(tcp, nullptr, nullptr);
        if (accepted != INVALID_SOCKET) closesocket(accepted);
        (void)recv(tcp, buffer, (int)sizeof(buffer), 0);
        (void)sendto(udp, buffer, 1, 0, reinterpret_cast<const sockaddr *>(&beacon),
            sizeof(beacon));
    }

    closesocket(udp);
    closesocket(tcp);
    return 0;
}

static int run_case(const wchar_t *dll, bool detailed) {
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return fail("WSAStartup", WSAGetLastError());
    if (LoadLibraryW(dll) == nullptr) return fail("LoadLibraryW", GetLastError());
    if (!wait_until_hooked(15)) return fail("the hook never answered a beacon", GetLastError());
    const int result = detailed ? run_virtual_flood() : 0;
    WSACleanup();
    return result;
}

static void write_ini(const wchar_t *directory, bool detailed) {
    char text[1024] = {};
    _snprintf_s(text, sizeof(text), _TRUNCATE,
        "[network]\r\n"
        "enable=1\r\n"
        "interface=\r\n"
        "exclusive=1\r\n"
        "allowLoopback=0\r\n"
        "forceDirectedBroadcast=1\r\n"
        "forceLimitedBroadcast=1\r\n"
        "virtualizeIcmp=1\r\n"
        "overrideBestRoute=1\r\n"
        "forceTcpSource=1\r\n"
        "strict=1\r\n"
        "\r\n"
        "[lanInstall]\r\n"
        "enable=1\r\n"
        "\r\n"
        "[segatools]\r\n"
        "path=\r\n"
        "\r\n"
        "[log]\r\n"
        "enable=1\r\n"
        "detailed=%d\r\n"
        "writeFile=1\r\n",
        detailed ? 1 : 0);

    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\network_hook.ini", directory) < 0) return;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(file, text, (DWORD)strlen(text), &written, nullptr);
    CloseHandle(file);
}

// The hook names its log after the moment it started, so the single *.log in
// `<dll dir>\network_hook_logs` is this run's.
static HANDLE open_log(const wchar_t *directory) {
    wchar_t pattern[MAX_PATH] = {};
    if (swprintf_s(pattern, L"%s\\network_hook_logs\\*.log", directory) < 0) return INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW entry = {};
    HANDLE find = FindFirstFileW(pattern, &entry);
    if (find == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    FindClose(find);

    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\network_hook_logs\\%s", directory, entry.cFileName) < 0)
        return INVALID_HANDLE_VALUE;
    return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static char *read_log(const wchar_t *directory) {
    HANDLE file = open_log(directory);
    if (file == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(file);
        return nullptr;
    }
    char *buffer = static_cast<char *>(calloc((size_t)size.QuadPart + 1, 1));
    if (buffer == nullptr) {
        CloseHandle(file);
        return nullptr;
    }
    DWORD read = 0;
    const bool ok = ReadFile(file, buffer, (DWORD)size.QuadPart, &read, nullptr) != 0;
    CloseHandle(file);
    if (!ok) {
        free(buffer);
        return nullptr;
    }
    buffer[read] = 0;
    return buffer;
}

// Fields are tab-separated and the category is the fifth, so a category is counted by
// position - matching a substring would also count message text that mentions it.
static int count_category(const char *log, const char *category) {
    const size_t category_length = strlen(category);
    int count = 0;
    const char *line = log;
    while (line != nullptr && *line != 0) {
        const char *end = strchr(line, '\n');
        const size_t line_length = end != nullptr ? (size_t)(end - line) : strlen(line);
        const char *field = line;
        bool found = true;
        for (int index = 0; index < 4; ++index) {
            const char *tab = static_cast<const char *>(
                memchr(field, '\t', line_length - (size_t)(field - line)));
            if (tab == nullptr) {
                found = false;
                break;
            }
            field = tab + 1;
        }
        if (found) {
            const size_t remaining = line_length - (size_t)(field - line);
            if (remaining > category_length &&
                memcmp(field, category, category_length) == 0 &&
                field[category_length] == '\t') {
                ++count;
            }
        }
        line = end != nullptr ? end + 1 : nullptr;
    }
    return count;
}

// For the flood case: the sum of the counts folded into the reported lines, which is how the
// probe proves the calls were absorbed rather than dropped.
static unsigned long long sum_folded(const char *log) {
    unsigned long long total = 0;
    const char *cursor = log;
    while ((cursor = strstr(cursor, "folded=")) != nullptr) {
        cursor += 7;
        total += _strtoui64(cursor, nullptr, 10);
    }
    return total;
}

static int check_concise(const char *log) {
    struct Marker { const char *text; const char *why; };
    const Marker markers[] = {
        { "[network_hook] STATUS", "the status line is not in the log file" },
        { "\tSTART\t", "no START line: which process and whether the hooks installed" },
        { "\tCONFIG\t", "no CONFIG line: the settings this run actually used" },
        { "architecture=", "no architecture in the start-up record" },
        { "LAN Install is virtualised", "the LAN Install decision is not stated" },
    };
    for (const Marker &marker : markers) {
        if (strstr(log, marker.text) == nullptr) {
            fprintf(stderr, "FAIL: %s (looking for \"%s\")\n", marker.why, marker.text);
            return 1;
        }
    }
    // A concise log that grows with traffic is not concise. The beacon probing in this
    // probe alone is a handful of lines; the flood of a real session is what `detailed` is
    // for, so anything close to a hundred lines means the split regressed.
    const int total = count_category(log, "INFO") + count_category(log, "START") +
        count_category(log, "CONFIG") + count_category(log, "ERROR") +
        count_category(log, "ADAPTER") + count_category(log, "LAN_VIRT");
    if (total > 40) {
        fprintf(stderr, "FAIL: concise logging produced %d lines; it should stay a handful\n", total);
        return 1;
    }
    if (count_category(log, "LAN_VIRT") != 0) {
        fputs("FAIL: LAN_VIRT detail lines appeared with detailed=0\n", stderr);
        return 1;
    }
    printf("  concise: %d lines, identity and decisions present, no per-call detail\n", total);
    return 0;
}

// Largest `virtual_tx_bytes=` in the log: the byte count carried on a CLOSE line for a
// socket whose sends this DLL answered itself.
static unsigned long long max_virtual_bytes(const char *log) {
    unsigned long long largest = 0;
    const char *cursor = log;
    while ((cursor = strstr(cursor, "virtual_tx_bytes=")) != nullptr) {
        cursor += strlen("virtual_tx_bytes=");
        const unsigned long long value = _strtoui64(cursor, nullptr, 10);
        if (value > largest) largest = value;
    }
    return largest;
}

static int check_flood(const char *log) {
    const int virtual_lines = count_category(log, "LAN_VIRT");
    const unsigned long long folded = sum_folded(log);
    if (strstr(log, "op=accept") == nullptr || strstr(log, "op=sendto") == nullptr) {
        fputs("FAIL: a virtualised operation was never reported at all\n", stderr);
        return 1;
    }
    if (virtual_lines > 20) {
        fprintf(stderr,
            "FAIL: 5015 virtualised calls became %d LAN_VIRT lines; repeats are not folded\n",
            virtual_lines);
        return 1;
    }
    if (folded < 4000) {
        fprintf(stderr,
            "FAIL: only %llu folded calls were accounted for; the repeated calls were dropped "
            "rather than counted\n", folded);
        return 1;
    }
    // The sends answered locally are counted apart from the real ones, so a socket that
    // carried 1005 virtual beacon bytes cannot close as "tx_bytes=0" and read as unused.
    const unsigned long long virtual_bytes = max_virtual_bytes(log);
    if (virtual_bytes < 1000) {
        fprintf(stderr,
            "FAIL: virtual_tx_bytes reached only %llu on a socket that sent 1005 bytes through "
            "the virtualised path\n", virtual_bytes);
        return 1;
    }
    printf("  5015 virtualised calls: %d LAN_VIRT lines, %llu repeats accounted for, "
        "%llu bytes counted as virtual\n", virtual_lines, folded, virtual_bytes);
    return 0;
}

// Prepares `<root>\<case>\`, copies the DLL there, and writes that case's ini. The child
// loads the copy, so it reads the configuration written for it.
static bool prepare_case(const wchar_t *root, const wchar_t *name, const wchar_t *dll,
        bool detailed, wchar_t *dll_out, size_t dll_out_count, const char **step) {
    wchar_t directory[MAX_PATH] = {};
    *step = "swprintf(dir)";
    if (swprintf_s(directory, L"%s\\%s", root, name) < 0) return false;
    *step = "CreateDirectory(root)";
    if (!CreateDirectoryW(root, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    *step = "CreateDirectory(case)";
    if (!CreateDirectoryW(directory, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;

    const wchar_t *leaf = wcsrchr(dll, L'\\');
    leaf = leaf == nullptr ? dll : leaf + 1;
    *step = "swprintf(dll_out)";
    if (swprintf_s(dll_out, dll_out_count, L"%s\\%s", directory, leaf) < 0) return false;
    *step = "CopyFile(dll)";
    if (!CopyFileW(dll, dll_out, FALSE)) return false;
    write_ini(directory, detailed);
    return true;
}

static void remove_case(const wchar_t *root, const wchar_t *name, const wchar_t *dll) {
    DeleteFileW(dll);
    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\%s\\network_hook.ini", root, name) >= 0) DeleteFileW(path);
    if (swprintf_s(path, L"%s\\%s\\network_hook_logs", root, name) >= 0) {
        WIN32_FIND_DATAW entry = {};
        wchar_t pattern[MAX_PATH] = {};
        if (swprintf_s(pattern, L"%s\\*.log", path) >= 0) {
            HANDLE find = FindFirstFileW(pattern, &entry);
            if (find != INVALID_HANDLE_VALUE) {
                do {
                    wchar_t file[MAX_PATH] = {};
                    if (swprintf_s(file, L"%s\\%s", path, entry.cFileName) >= 0) DeleteFileW(file);
                } while (FindNextFileW(find, &entry));
                FindClose(find);
            }
        }
        RemoveDirectoryW(path);
    }
    if (swprintf_s(path, L"%s\\%s", root, name) >= 0) RemoveDirectoryW(path);
}

// Runs one case in a child process and returns its log for inspection.
static char *run_and_read(const wchar_t *self, const wchar_t *dll, const wchar_t *root,
        const wchar_t *name, int *failures) {
    wchar_t command[MAX_PATH * 3] = {};
    if (swprintf_s(command, L"\"%s\" --child \"%s\" %s", self, dll, name) < 0) return nullptr;
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(nullptr, command, nullptr, nullptr, TRUE, 0, nullptr, nullptr,
            &startup, &process)) {
        return nullptr;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (code != 0) {
        ++*failures;
        return nullptr;
    }
    wchar_t directory[MAX_PATH] = {};
    if (swprintf_s(directory, L"%s\\%s", root, name) < 0) return nullptr;
    return read_log(directory);
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 4 && wcscmp(argv[1], L"--child") == 0) {
        return run_case(argv[2], wcscmp(argv[3], L"detail") == 0);
    }
    if (argc != 2) {
        fwprintf(stderr, L"usage: %s <hook.dll>\n", argv[0]);
        return 2;
    }

    wchar_t self[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) == 0) return fail("GetModuleFileNameW", GetLastError());

    // Beside the DLL rather than in %TEMP%, so the scratch copy stays next to the build
    // output it came from, as probe_ownership does.
    wchar_t root[MAX_PATH] = {};
    if (swprintf_s(root, L"%s", argv[1]) < 0) return fail("building the scratch path", ERROR_BUFFER_OVERFLOW);
    wchar_t *leaf = wcsrchr(root, L'\\');
    if (leaf == nullptr) return fail("the hook path has no directory", ERROR_BAD_PATHNAME);
    *leaf = L'\0';
    const size_t root_length = wcslen(root);
    if (swprintf_s(root + root_length, MAX_PATH - root_length, L"\\probe_logging_scratch") < 0)
        return fail("building the scratch path", ERROR_BUFFER_OVERFLOW);

    wchar_t concise_dll[MAX_PATH] = {};
    wchar_t detail_dll[MAX_PATH] = {};
    const char *step = "";
    if (!prepare_case(root, L"concise", argv[1], false, concise_dll, MAX_PATH, &step)) {
        fprintf(stderr, "  root=%ws\n", root);
        return fail(step, GetLastError());
    }
    if (!prepare_case(root, L"detail", argv[1], true, detail_dll, MAX_PATH, &step)) {
        fprintf(stderr, "  root=%ws\n", root);
        return fail(step, GetLastError());
    }

    puts("probe_logging: what the two log levels are for");
    int failures = 0;
    int child_failures = 0;
    char *concise = run_and_read(self, concise_dll, root, L"concise", &child_failures);
    char *detail = run_and_read(self, detail_dll, root, L"detail", &child_failures);
    failures += child_failures;

    if (concise == nullptr) {
        if (child_failures == 0) fputs("FAIL: detailed=0 left no log file at all\n", stderr);
        ++failures;
    } else if (check_concise(concise) != 0) {
        ++failures;
    }
    if (detail == nullptr) {
        if (child_failures == 0) fputs("FAIL: detailed=1 left no log file\n", stderr);
        ++failures;
    } else if (check_flood(detail) != 0) {
        ++failures;
    }

    free(concise);
    free(detail);
    remove_case(root, L"concise", concise_dll);
    remove_case(root, L"detail", detail_dll);
    RemoveDirectoryW(root);

    if (failures != 0) {
        fprintf(stderr, "FAIL: %d logging check(s) disagreed\n", failures);
        return 1;
    }
    puts("PASS: concise logging keeps the identity and decisions, detailed logging folds repeats");
    return 0;
}
