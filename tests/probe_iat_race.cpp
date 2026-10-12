// A/B probe: measures what GetAdaptersAddresses returns at the moment the hook's
// initialize thread runs, so the v0.1.0 vs HEAD difference can be observed without
// launching the game. The probe deliberately mimics the hook's startup ordering:
//   DllMain -> CreateThread(initialize) -> resolve_network_interface -> log_adapters
// It loads the DLL under test and then, from the main thread, polls
// GetAdaptersAddresses repeatedly and records the first moment at which the adapter
// list shrinks to the netenv synthetic one (IfIndex == 1, "Fake Ethernet").
//
// Build (x86, because chusanApp.exe is x86):
//   cl /nologo /std:c++17 /O2 /MT /W4 /DWIN32 /D_WINDOWS probe_iat_race.cpp
//      /link ws2_32.lib iphlpapi.lib
//
// Usage: probe_iat_race.exe <path\to\chusan_network_hook_x86.dll>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {

struct Snapshot {
    ULONG count;
    ULONG first_index;
    char first_name[256];
    bool has_fake_ethernet;
};

Snapshot snapshot_adapters() {
    Snapshot s = {};
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buffer(size);
    ULONG result = GetAdaptersAddresses(AF_INET,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER, nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        result = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
    }
    if (result != NO_ERROR) {
        s.count = 0;
        return s;
    }
    for (IP_ADAPTER_ADDRESSES *a = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
         a != nullptr; a = a->Next) {
        if (s.count == 0) {
            s.first_index = a->IfIndex;
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                s.first_name, sizeof(s.first_name), nullptr, nullptr);
        }
        ++s.count;
        if (a->IfIndex == 1 && a->FriendlyName != nullptr) {
            char name[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                name, sizeof(name), nullptr, nullptr);
            if (strstr(name, "Fake Ethernet") != nullptr) s.has_fake_ethernet = true;
        }
    }
    return s;
}

const char *phase_name(int i) {
    switch (i) {
    case 0: return "immediately-after-LoadLibrary";
    case 1: return "after-10ms";
    case 2: return "after-50ms";
    case 3: return "after-100ms";
    case 4: return "after-250ms";
    case 5: return "after-500ms";
    case 6: return "after-1000ms";
    default: return "later";
    }
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hook dll>\n", argv[0]);
        return 2;
    }
    const int delays_ms[] = {0, 10, 50, 100, 250, 500, 1000, 2000};
    const int phase_count = sizeof(delays_ms) / sizeof(delays_ms[0]);

    Snapshot before = snapshot_adapters();
    printf("before LoadLibrary : count=%lu first_index=%lu first_name=\"%s\" fake=%d\n",
        before.count, before.first_index, before.first_name,
        before.has_fake_ethernet ? 1 : 0);
    fflush(stdout);

    HMODULE dll = LoadLibraryA(argv[1]);
    if (dll == nullptr) {
        fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    printf("LoadLibrary        : ok (%s)\n", argv[1]);
    fflush(stdout);

    for (int i = 0; i < phase_count; ++i) {
        if (delays_ms[i] > 0) Sleep(delays_ms[i] - delays_ms[i - 1]);
        Snapshot s = snapshot_adapters();
        printf("%-26s: count=%lu first_index=%lu first_name=\"%s\" fake=%d\n",
            phase_name(i), s.count, s.first_index, s.first_name,
            s.has_fake_ethernet ? 1 : 0);
        fflush(stdout);
    }

    FreeLibrary(dll);
    return 0;
}
