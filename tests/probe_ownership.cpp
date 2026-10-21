// Probe: who owns the network, asserted by effect rather than by reading the log.
//
// `[netenv] enable=1` in segatools.ini hands the network to segatools. This hook must then
// present nothing and pin nothing, while LAN Install virtualisation -- which has no
// counterpart in segatools -- keeps following its own switch. Two effects make that
// checkable:
//
//   * a beacon to UDP 40112 answers without reaching the stack. That virtual return is taken
//     before any pin, so it doubles as a readiness signal in both configurations: it proves
//     this build is loaded and its hooks are in place.
//   * a broadcast to UDP 50200 is either blocked by strict mode (this hook pinned it) or
//     reaches the real stack (it did not). 50200 is Party, outside LAN Install, so it is
//     never virtualised and always reaches the pin.
//
// The two configurations need separate processes: the hook reads its ini from its own
// directory in DllMain, and two copies of it cannot coexist in one process. The parent
// prepares a directory per case and re-executes itself into it.
//
// Usage: probe_ownership <hook.dll>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <string.h>

static const char *kIni =
    "[network]\r\n"
    "enable=1\r\n"
    "interface=192.0.2.99\r\n"
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
    "detailed=0\r\n"
    "writeFile=0\r\n";

static int fail(const char *what, DWORD error) {
    fprintf(stderr, "FAIL: %s (%lu)\n", what, error);
    return 1;
}

// True once the hook answers a LAN Install beacon. That return is taken before the pin, so
// it says nothing about ownership -- only that the import table has been patched.
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

// Sends one broadcast on the Party port and returns the error the caller sees. No
// SO_BROADCAST is set, so an unpinned broadcast is rejected by the stack with WSAEACCES,
// while a pinned one that cannot be pinned is refused by this hook with WSAENETUNREACH.
static int broadcast_party_beacon(int *error) {
    *error = 0;
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        *error = WSAGetLastError();
        return SOCKET_ERROR;
    }
    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_port = htons(50200);
    to.sin_addr.s_addr = INADDR_BROADCAST;
    const char byte = 0;
    WSASetLastError(0);
    const int sent = sendto(udp, &byte, 1, 0,
        reinterpret_cast<const sockaddr *>(&to), sizeof(to));
    *error = WSAGetLastError();
    closesocket(udp);
    return sent;
}

// Runs in the prepared directory. `expect_segatools` says which component should own the
// network there, so the same assertions cover both directions of the rule.
static int run_case(const wchar_t *dll, bool expect_segatools) {
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return fail("WSAStartup", WSAGetLastError());
    if (LoadLibraryW(dll) == nullptr) return fail("LoadLibraryW", GetLastError());
    if (!wait_until_hooked(15)) return fail("the hook never answered a beacon", GetLastError());

    int error = 0;
    const int sent = broadcast_party_beacon(&error);
    const int wanted = expect_segatools ? WSAEACCES : WSAENETUNREACH;
    if (sent != SOCKET_ERROR || error != wanted) {
        fprintf(stderr,
            "FAIL: broadcast to UDP 50200 returned %d/%d, expected a failure with %d (%s)\n",
            sent, error, wanted,
            expect_segatools ? "not pinned: segatools owns the network"
                             : "pinned and blocked: this hook owns the network");
        return 1;
    }
    printf("  %s: 50200 broadcast refused with %d, as expected\n",
        expect_segatools ? "segatools owns it" : "hook owns it", error);
    WSACleanup();
    return 0;
}

// Prepares `<root>\<case>\`, copies the DLL there and writes the pair of ini files. The
// child then loads the copy, so it reads the configuration written for it.
static bool prepare_case(const wchar_t *root, const wchar_t *name, const wchar_t *dll,
        bool netenv, wchar_t *dll_out, size_t dll_out_count, const char **step) {
    *step = "swprintf(dir)";
    wchar_t dir[MAX_PATH] = {};
    if (swprintf_s(dir, L"%s\\%s", root, name) < 0) { *step = "swprintf(dir)"; return false; }
    *step = "CreateDirectory(root)";
    if (!CreateDirectoryW(root, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    *step = "CreateDirectory(dir)";
    if (!CreateDirectoryW(dir, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;

    const wchar_t *leaf = wcsrchr(dll, L'\\');
    leaf = leaf == nullptr ? dll : leaf + 1;
    if (swprintf_s(dll_out, dll_out_count, L"%s\\%s", dir, leaf) < 0) {
        *step = "swprintf(dll_out)";
        return false;
    }
    *step = "CopyFile(dll)";
    if (!CopyFileW(dll, dll_out, FALSE)) return false;

    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\network_hook.ini", dir) < 0) {
        *step = "swprintf(network_hook.ini)";
        return false;
    }
    *step = "CreateFile(network_hook.ini)";
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const DWORD length = (DWORD)strlen(kIni);
    *step = "WriteFile(network_hook.ini)";
    const bool ok = WriteFile(file, kIni, length, &written, nullptr) && written == length;
    CloseHandle(file);
    if (!ok) return false;

    if (swprintf_s(path, L"%s\\segatools.ini", dir) < 0) {
        *step = "swprintf(segatools.ini)";
        return false;
    }
    *step = "CreateFile(segatools.ini)";
    file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    char segatools_ini[64] = {};
    _snprintf_s(segatools_ini, sizeof(segatools_ini), _TRUNCATE,
        "[netenv]\nenable=%d\n\n[keychip]\nsubnet=192.168.139.0\n", netenv ? 1 : 0);
    const DWORD segatools_length = (DWORD)strlen(segatools_ini);
    written = 0;
    *step = "WriteFile(segatools.ini)";
    const bool ok2 = WriteFile(file, segatools_ini, segatools_length, &written, nullptr) &&
        written == segatools_length;
    CloseHandle(file);
    return ok2;
}

// Takes the scratch copy back out again, so the build directory keeps holding only what
// build.bat produced.
static void remove_case(const wchar_t *root, const wchar_t *name, const wchar_t *dll) {
    DeleteFileW(dll);
    wchar_t path[MAX_PATH] = {};
    if (swprintf_s(path, L"%s\\%s\\network_hook.ini", root, name) >= 0) DeleteFileW(path);
    if (swprintf_s(path, L"%s\\%s\\segatools.ini", root, name) >= 0) DeleteFileW(path);
    if (swprintf_s(path, L"%s\\%s", root, name) >= 0) RemoveDirectoryW(path);
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 4 && wcscmp(argv[1], L"--child") == 0) {
        return run_case(argv[2], wcscmp(argv[3], L"segatools") == 0);
    }
    if (argc != 2) {
        fwprintf(stderr, L"usage: %s <hook.dll>\n", argv[0]);
        return 2;
    }

    wchar_t self[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, self, MAX_PATH) == 0) return fail("GetModuleFileNameW", GetLastError());

    // Beside the DLL it was given rather than in %TEMP%: the build directory is writable
    // in every context this probe runs in, and it keeps the scratch copy next to the build
    // output it came from.
    wchar_t root[MAX_PATH] = {};
    if (swprintf_s(root, L"%s", argv[1]) < 0) return fail("building the scratch path", ERROR_BUFFER_OVERFLOW);
    wchar_t *leaf = wcsrchr(root, L'\\');
    if (leaf == nullptr) return fail("the hook path has no directory", ERROR_BAD_PATHNAME);
    *leaf = L'\0';
    const size_t root_length = wcslen(root);
    if (swprintf_s(root + root_length, MAX_PATH - root_length, L"\\probe_ownership_scratch") < 0) {
        return fail("building the scratch path", ERROR_BUFFER_OVERFLOW);
    }

    const char *step = "";
    wchar_t dll[MAX_PATH] = {};
    if (!prepare_case(root, L"segatools", argv[1], true, dll, MAX_PATH, &step)) {
        fprintf(stderr, "  root=%ws\n", root);
        return fail(step, GetLastError());
    }
    wchar_t dll2[MAX_PATH] = {};
    if (!prepare_case(root, L"hook", argv[1], false, dll2, MAX_PATH, &step)) {
        fprintf(stderr, "  root=%ws\n", root);
        return fail(step, GetLastError());
    }

    puts("probe_ownership: who owns the network");
    int failures = 0;
    const wchar_t *cases[] = { L"segatools", L"hook" };
    const wchar_t *copies[] = { dll, dll2 };
    for (int i = 0; i < 2; ++i) {
        wchar_t command[MAX_PATH * 3] = {};
        if (swprintf_s(command, L"\"%s\" --child \"%s\" %s", self, copies[i], cases[i]) < 0) {
            return fail("building the child command line", ERROR_BUFFER_OVERFLOW);
        }
        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process = {};
        if (!CreateProcessW(nullptr, command, nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                &startup, &process)) {
            return fail("CreateProcessW", GetLastError());
        }
        WaitForSingleObject(process.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(process.hProcess, &code);
        if (code != 0) ++failures;
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }

    remove_case(root, L"segatools", dll);
    remove_case(root, L"hook", dll2);
    RemoveDirectoryW(root);

    if (failures != 0) {
        fprintf(stderr, "FAIL: %d of 2 cases disagreed\n", failures);
        return 1;
    }
    puts("PASS: netenv=1 pins nothing, netenv=0 pins, and LAN Install virtualisation runs in both");
    return 0;
}
