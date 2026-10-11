#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>

#include "interface_resolution.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static int fail(const char *step, int error) {
    fprintf(stderr, "FAIL: %s (%d)\n", step, error);
    return 1;
}

// The interface-index decision table. This is where a future segatools release that
// virtualizes GetIpAddrTable or GetBestRoute2 would surface, so the behaviour on each
// combination is pinned down here rather than only being exercised on a live host.
static int test_interface_decision_table() {
    struct Case {
        const char *label;
        bool table_found;
        unsigned long table_index;
        bool route_found;
        unsigned long route_index;
        InterfaceResolution expected;
        unsigned long expected_index;
    };
    const Case cases[] = {
        {"both agree",                 true,  10, true,  10, kInterfaceResolvedFromTable, 10},
        {"both agree on loopback",     true,   1, true,   1, kInterfaceResolvedFromTable,  1},
        {"disagree, table wins",       true,  10, true,   1, kInterfaceResolvedFromTable, 10},
        {"disagree, table wins rev",   true,   7, true,  20, kInterfaceResolvedFromTable,  7},
        {"table only",                 true,  20, false,  0, kInterfaceResolvedFromTable, 20},
        {"route only",                 false,  0, true,  20, kInterfaceResolvedFromRoute, 20},
        {"neither, must refuse",       false,  0, false,  0, kInterfaceUnresolved,         0},
        {"virtualized index 1 caught", true,  20, true,   1, kInterfaceResolvedFromTable, 20},
    };

    for (const Case &c : cases) {
        unsigned long index = 0xDEADBEEFul;
        const InterfaceResolution got = decide_interface_index(
            c.table_found, c.table_index, c.route_found, c.route_index, &index);
        if (got != c.expected || index != c.expected_index) {
            fprintf(stderr, "FAIL: interface decision '%s': got resolution=%d index=%lu, "
                "expected resolution=%d index=%lu\n",
                c.label, (int)got, index, (int)c.expected, c.expected_index);
            return 1;
        }
    }

    // A null out-pointer must not crash, since callers may only want the verdict.
    const InterfaceResolution null_out = decide_interface_index(true, 5, true, 5, nullptr);
    if (null_out != kInterfaceResolvedFromTable) {
        fprintf(stderr, "FAIL: interface decision with null out_index returned %d\n", (int)null_out);
        return 1;
    }

    printf("PASS: interface index decision table (%zu cases)\n",
        sizeof(cases) / sizeof(cases[0]));
    return 0;
}

static int test_party_loopback() {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return fail("party loopback listener socket", WSAGetLastError());

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(50200);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR)
        return fail("party loopback bind", WSAGetLastError());
    if (listen(listener, 2) == SOCKET_ERROR)
        return fail("party loopback listen", WSAGetLastError());

    for (int use_wsa_connect = 0; use_wsa_connect < 2; ++use_wsa_connect) {
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client == INVALID_SOCKET) return fail("party loopback client socket", WSAGetLastError());
        const int result = use_wsa_connect
            ? WSAConnect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address),
                nullptr, nullptr, nullptr, nullptr)
            : connect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
        if (result == SOCKET_ERROR)
            return fail(use_wsa_connect ? "party loopback WSAConnect" : "party loopback connect",
                WSAGetLastError());
        SOCKET accepted = accept(listener, nullptr, nullptr);
        if (accepted == INVALID_SOCKET) return fail("party loopback accept", WSAGetLastError());
        closesocket(accepted);
        closesocket(client);
    }

    closesocket(listener);
    return 0;
}

// Reads the interface index that the hook pinned this socket to, in host byte order.
// Zero means no interface forcing was applied to the socket.
static DWORD pinned_interface_index(SOCKET s) {
    DWORD index = 0;
    int length = sizeof(index);
    if (getsockopt(s, IPPROTO_IP, IP_UNICAST_IF,
            reinterpret_cast<char *>(&index), &length) == SOCKET_ERROR) {
        return 0;
    }
    return index;
}

// Result of one broadcast probe.
struct ProbeResult {
    bool socket_failed;   // the probe itself could not run; not a verdict about the hook
    bool send_failed;     // sendto was rejected, which strict mode does on purpose
    int send_error;
    long pinned_index;    // interface index the hook selected, 0 when none was applied
};

// Sends one datagram to a broadcast address and reports the interface index the hook
// selected for that socket. A rejected sendto is reported rather than treated as a
// failure, because strict mode blocking the packet is the expected outcome for an
// unusable interfaceAddress.
static ProbeResult probe_broadcast(const char *destination_text, unsigned short port) {
    ProbeResult result = {};
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        result.socket_failed = true;
        result.send_error = WSAGetLastError();
        return result;
    }

    BOOL enabled = TRUE;
    if (setsockopt(udp, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == SOCKET_ERROR) {
        result.socket_failed = true;
        result.send_error = WSAGetLastError();
        closesocket(udp);
        return result;
    }

    sockaddr_in destination = {};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    if (InetPtonA(AF_INET, destination_text, &destination.sin_addr) != 1) {
        result.socket_failed = true;
        result.send_error = WSAGetLastError();
        closesocket(udp);
        return result;
    }

    const char payload[] = "broadcast probe";
    const int sent = sendto(udp, payload, (int)sizeof(payload), 0,
        reinterpret_cast<const sockaddr *>(&destination), sizeof(destination));
    if (sent != (int)sizeof(payload)) {
        result.send_failed = true;
        result.send_error = WSAGetLastError();
        closesocket(udp);
        return result;
    }

    result.pinned_index = static_cast<long>(pinned_interface_index(udp));
    closesocket(udp);
    return result;
}

// Locates the real interface index and mask for an address using GetIpAddrTable, which
// segatools' netenv does not hook. Returns false when the address is not local.
static bool local_interface_for(const char *address_text, DWORD *index, DWORD *mask) {
    in_addr address = {};
    if (InetPtonA(AF_INET, address_text, &address) != 1) return false;

    ULONG size = 0;
    if (GetIpAddrTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER || size == 0) return false;
    MIB_IPADDRTABLE *table = static_cast<MIB_IPADDRTABLE *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
    if (table == nullptr) return false;

    bool found = false;
    if (GetIpAddrTable(table, &size, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            if (table->table[i].dwAddr != address.s_addr) continue;
            *index = table->table[i].dwIndex;
            *mask = table->table[i].dwMask;
            found = true;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, table);
    return found;
}

// Regression coverage for broadcast interface forcing.
//
// The game announces to the subnet's directed broadcast (for example 192.168.139.255),
// not to 255.255.255.255, so both must be recognized. When the optional
// interfaceAddress argument names an address the real IP stack owns, both must pin that
// address's real interface index; an unrelated broadcast must never be pinned.
//
// The netenv-virtualization scenario itself is covered deterministically by
// test_interface_decision_table, because this process does not load segatools.
static int test_broadcast_interface_forcing(int argc, wchar_t **argv) {
    const ProbeResult unrelated = probe_broadcast("10.99.99.255", 50202);
    if (unrelated.socket_failed) {
        return fail("unrelated broadcast probe socket", unrelated.send_error);
    }
    if (unrelated.send_failed) {
        // An unrelated destination is never a forcing target, so strict mode must not
        // interfere with it either.
        fprintf(stderr, "FAIL: unrelated broadcast send was rejected (%d); strict mode "
            "should not apply to a non-broadcast-target destination\n", unrelated.send_error);
        return 1;
    }

    // Holds for every configuration: forcing is scoped to the configured interface's
    // broadcast address, so an unrelated subnet broadcast is never touched.
    if (unrelated.pinned_index != 0) {
        fprintf(stderr, "FAIL: unrelated broadcast was pinned to index %ld\n",
            unrelated.pinned_index);
        return 1;
    }

    if (argc < 3) {
        printf("PASS: unrelated broadcast left unpinned "
            "(no interfaceAddress argument; limited/directed not asserted)\n");
        return 0;
    }

    char address_text[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, address_text, sizeof(address_text), nullptr, nullptr);

    DWORD index = 0;
    DWORD mask = 0;
    const bool in_real_stack = local_interface_for(address_text, &index, &mask);
    const ProbeResult limited = probe_broadcast("255.255.255.255", 50200);
    if (limited.socket_failed) {
        return fail("limited broadcast probe socket", limited.send_error);
    }

    if (!in_real_stack) {
        // No real interface owns this address, so under strict=1 the hook must refuse to
        // select an interface and block a forcing target rather than fall back to
        // Windows routing.
        if (!limited.send_failed) {
            fprintf(stderr, "FAIL: expected strict mode to block %s, but sendto succeeded "
                "with pinned index %ld\n", address_text, limited.pinned_index);
            return 1;
        }
        printf("PASS: strict mode blocked the limited broadcast for %s, which no real "
            "interface owns (%d)\n", address_text, limited.send_error);
        return 0;
    }

    if (limited.send_failed) {
        fprintf(stderr, "FAIL: limited broadcast to a usable interfaceAddress %s was "
            "rejected (%d)\n", address_text, limited.send_error);
        return 1;
    }
    if (limited.pinned_index != static_cast<long>(index)) {
        fprintf(stderr, "FAIL: limited broadcast pinned index %ld, expected %lu for %s\n",
            limited.pinned_index, static_cast<unsigned long>(index), address_text);
        return 1;
    }

    // A host mask (/32, as used by some VPN adapters) has no directed broadcast, so there
    // is nothing further to assert beyond the limited broadcast above.
    const bool subnet_mask = mask != 0 && mask != 0xFFFFFFFFu && (~mask & 1u) == 0;
    if (!subnet_mask) {
        printf("PASS: limited broadcast pinned interface index %lu for %s "
            "(no directed broadcast for mask 0x%08lX)\n",
            static_cast<unsigned long>(index), address_text, static_cast<unsigned long>(mask));
        return 0;
    }

    in_addr configured = {};
    InetPtonA(AF_INET, address_text, &configured);
    in_addr directed_address = {};
    directed_address.s_addr = configured.s_addr | ~mask;

    char directed_text[64] = {};
    const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&directed_address.s_addr);
    sprintf_s(directed_text, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);

    const ProbeResult directed = probe_broadcast(directed_text, 50201);
    if (directed.socket_failed) {
        return fail("directed broadcast probe socket", directed.send_error);
    }
    if (directed.send_failed) {
        fprintf(stderr, "FAIL: directed broadcast %s was rejected (%d)\n",
            directed_text, directed.send_error);
        return 1;
    }
    if (directed.pinned_index != static_cast<long>(index)) {
        fprintf(stderr, "FAIL: directed broadcast %s pinned index %ld, expected %lu\n",
            directed_text, directed.pinned_index, static_cast<unsigned long>(index));
        return 1;
    }

    printf("PASS: limited broadcast and directed broadcast %s both pinned interface index %lu\n",
        directed_text, static_cast<unsigned long>(index));
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        fwprintf(stderr, L"Usage: %s <hook.dll> [interfaceAddress]\n", argv[0]);
        return 2;
    }
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return fail("WSAStartup", WSAGetLastError());
    HMODULE hook = LoadLibraryW(argv[1]);
    if (hook == nullptr) return fail("LoadLibraryW", GetLastError());
    Sleep(300);

    if (test_interface_decision_table() != 0) return 1;
    if (test_party_loopback() != 0) return 1;
    if (test_broadcast_interface_forcing(argc, argv) != 0) return 1;

    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) return fail("UDP socket", WSAGetLastError());
    sockaddr_in beacon = {};
    beacon.sin_family = AF_INET;
    beacon.sin_port = htons(40112);
    beacon.sin_addr.s_addr = INADDR_BROADCAST;
    const char payload[] = "virtual beacon";
    const int sent = sendto(udp, payload, (int)sizeof(payload), 0,
        reinterpret_cast<const sockaddr *>(&beacon), sizeof(beacon));
    if (sent != (int)sizeof(payload)) return fail("virtual UDP beacon", WSAGetLastError());

    closesocket(udp);

    SOCKET tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp == INVALID_SOCKET) return fail("TCP socket", WSAGetLastError());
    sockaddr_in sync = {};
    sync.sin_family = AF_INET;
    sync.sin_port = htons(40110);
    sync.sin_addr.s_addr = INADDR_ANY;
    if (bind(tcp, reinterpret_cast<const sockaddr *>(&sync), sizeof(sync)) == SOCKET_ERROR)
        return fail("virtual TCP bind", WSAGetLastError());
    if (listen(tcp, 4) == SOCKET_ERROR) return fail("virtual TCP listen", WSAGetLastError());
    SOCKET accepted = accept(tcp, nullptr, nullptr);
    if (accepted != INVALID_SOCKET || WSAGetLastError() != WSAEWOULDBLOCK)
        return fail("virtual TCP accept", WSAGetLastError());
    closesocket(tcp);

    WSACleanup();
    puts("PASS: loopback Party and LAN Install virtualization smoke tests");
    return 0;
}
