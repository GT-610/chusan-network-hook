#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static int fail(const char *step, int error) {
    fprintf(stderr, "FAIL: %s (%d)\n", step, error);
    return 1;
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

// Sends one datagram to a broadcast address and reports the interface index that the
// hook selected for that socket. Returns -1 on a hard socket failure.
static long probe_broadcast(const char *label, const char *destination_text, unsigned short port) {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        fprintf(stderr, "FAIL: %s socket (%d)\n", label, WSAGetLastError());
        return -1;
    }

    BOOL enabled = TRUE;
    if (setsockopt(udp, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char *>(&enabled), sizeof(enabled)) == SOCKET_ERROR) {
        fprintf(stderr, "FAIL: %s SO_BROADCAST (%d)\n", label, WSAGetLastError());
        closesocket(udp);
        return -1;
    }

    sockaddr_in destination = {};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    if (InetPtonA(AF_INET, destination_text, &destination.sin_addr) != 1) {
        fprintf(stderr, "FAIL: %s InetPtonA (%d)\n", label, WSAGetLastError());
        closesocket(udp);
        return -1;
    }

    const char payload[] = "broadcast probe";
    const int sent = sendto(udp, payload, (int)sizeof(payload), 0,
        reinterpret_cast<const sockaddr *>(&destination), sizeof(destination));
    if (sent != (int)sizeof(payload)) {
        fprintf(stderr, "FAIL: %s sendto (%d)\n", label, WSAGetLastError());
        closesocket(udp);
        return -1;
    }

    const DWORD index = pinned_interface_index(udp);
    closesocket(udp);
    return static_cast<long>(index);
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
// interfaceAddress argument names a local address and the hook has interface forcing
// enabled, the directed broadcast must pin that address's real interface index; an
// unrelated broadcast must never be pinned.
static int test_broadcast_interface_forcing(int argc, wchar_t **argv) {
    const long limited = probe_broadcast("limited broadcast probe", "255.255.255.255", 50200);
    const long unrelated = probe_broadcast("unrelated broadcast probe", "10.99.99.255", 50202);
    if (limited < 0 || unrelated < 0) return 1;

    // Holds for every configuration: forcing is scoped to the configured interface's
    // broadcast address, so an unrelated subnet broadcast is never touched.
    if (unrelated != 0) {
        fprintf(stderr, "FAIL: unrelated broadcast was pinned to index %ld\n", unrelated);
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
    const bool usable = local_interface_for(address_text, &index, &mask) &&
        mask != 0 && mask != 0xFFFFFFFFu;

    if (!usable) {
        // strict=1 must refuse to pin anything when the configured address cannot be used.
        if (limited != 0) {
            fprintf(stderr, "FAIL: forcing applied for unusable interfaceAddress %s (limited=%ld)\n",
                address_text, limited);
            return 1;
        }
        printf("PASS: no forcing for unusable interfaceAddress %s\n", address_text);
        return 0;
    }

    in_addr configured = {};
    InetPtonA(AF_INET, address_text, &configured);
    in_addr directed_address = {};
    directed_address.s_addr = configured.s_addr | ~mask;

    char directed_text[64] = {};
    const unsigned char *bytes = reinterpret_cast<const unsigned char *>(&directed_address.s_addr);
    sprintf_s(directed_text, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);

    const long directed = probe_broadcast("directed broadcast", directed_text, 50201);
    if (directed < 0) return 1;

    if (limited != static_cast<long>(index) || directed != static_cast<long>(index)) {
        fprintf(stderr, "FAIL: expected index %lu for limited and directed (%s) broadcast, "
            "got limited=%ld directed=%ld\n",
            static_cast<unsigned long>(index), directed_text, limited, directed);
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
