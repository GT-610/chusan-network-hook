#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

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

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
        fwprintf(stderr, L"Usage: %s <hook.dll>\n", argv[0]);
        return 2;
    }
    WSADATA data = {};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return fail("WSAStartup", WSAGetLastError());
    HMODULE hook = LoadLibraryW(argv[1]);
    if (hook == nullptr) return fail("LoadLibraryW", GetLastError());
    Sleep(300);

    if (test_party_loopback() != 0) return 1;

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

    BOOL broadcast_enabled = TRUE;
    if (setsockopt(udp, SOL_SOCKET, SO_BROADCAST,
        reinterpret_cast<const char *>(&broadcast_enabled), sizeof(broadcast_enabled)) == SOCKET_ERROR)
        return fail("SO_BROADCAST", WSAGetLastError());
    beacon.sin_port = htons(50201);
    const int game_sent = sendto(udp, payload, (int)sizeof(payload), 0,
        reinterpret_cast<const sockaddr *>(&beacon), sizeof(beacon));
    if (game_sent != (int)sizeof(payload)) return fail("game limited broadcast", WSAGetLastError());
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
